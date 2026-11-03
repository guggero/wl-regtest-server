package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/lightningnetwork/lnd/zpay32"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// swapLifetime bounds admission independently of a long-lived BOLT11
	// invoice.
	swapLifetime = 10 * time.Minute

	// swapRefundBlocks allows the client's full ancestry and unilateral
	// claim.
	swapRefundBlocks = 288

	// paymentTimeout bounds the regtest Lightning routing attempt.
	paymentTimeout = 30 * time.Second
)

// inSwap tracks an Ark-to-Lightning send from the wallet's perspective.
// awaiting-funding waits for the sender's vHTLC, paying reconciles the
// Lightning outcome, and claiming recovers treasury value with the returned
// preimage. Direct same-Ark sends use in-ark while waiting for the receiver's
// claim. A failed attempt is never retried after refund authorization.
type inSwap struct {
	Request      *swaprpc.CreateInSwapRequest
	Response     *swaprpc.CreateInSwapResponse
	Account      string
	CreditID     string
	Policy       []byte
	Script       []byte
	Outpoint     string
	Phase        string
	Preimage     []byte
	Failure      string
	ClaimSession string
	InArk        bool
	Bridge       bool
}

// decodeInvoice validates an exact whole-satoshi regtest invoice before either
// quoting or committing swap resources.
func (s *Server) decodeInvoice(encoded string) (*zpay32.Invoice, uint64,
	error) {

	if len(
		encoded,
	) > 16000 {

		return nil, 0, status.Error(
			codes.InvalidArgument, "invoice too long",
		)
	}

	// Decode against regtest and require whole satoshis because Ark outputs
	// and credit balances cannot represent a fractional-satoshi invoice.
	invoice, err := zpay32.Decode(encoded, &chaincfg.RegressionNetParams)
	if err != nil {
		return nil, 0, status.Error(
			codes.InvalidArgument, "invalid regtest invoice",
		)
	}
	if invoice.MilliSat == nil || *invoice.MilliSat <= 0 ||
		uint64(*invoice.MilliSat)%1000 != 0 ||
		uint64(*invoice.MilliSat)/1000 > btcutil.MaxSatoshi {

		return nil, 0, status.Error(
			codes.InvalidArgument,
			"positive whole-satoshi invoice required",
		)
	}

	// Admission must not initiate payment of an already expired invoice;
	// quote and execution both use this check to avoid divergent terms.
	if !s.cfg.Clock.Now().Before(invoice.Timestamp.Add(
		invoice.Expiry(),
	)) {

		return nil, 0, status.Error(
			codes.FailedPrecondition, "invoice expired",
		)
	}
	return invoice, uint64(*invoice.MilliSat) / 1000, nil
}

// creditQuote applies only authorized credit and keeps any residual vHTLC at
// the advertised minimum. Dust invoices require their full amount in credits.
// All arguments and result amounts are satoshis; maximum is the caller's
// authorized cap, not an instruction to consume every available credit.
func (s *Server) creditQuote(
	amount, available, maximum uint64) *swaprpc.CreditQuote {

	q := &swaprpc.CreditQuote{ArkFundingSat: amount}
	limit := min(available, maximum)
	floor := uint64(s.cfg.MinAmount)

	// A subminimum invoice cannot be represented by a vHTLC at all. Report
	// its credit shortfall and a top-up large enough to form an Ark output.
	if amount < floor {
		q.MustUseCredit = true
		q.CreditAppliedSat = min(amount, limit)
		q.CreditShortfallSat = amount - q.CreditAppliedSat
		q.ArkFundingSat = 0
		if q.CreditShortfallSat > 0 {
			q.CreditTopupSat = max(floor, q.CreditShortfallSat)
		}
		return q
	}

	// Full credit funding needs no virtual output; partial credit must
	// leave at least the minimum amount in the sender-funded vHTLC.
	if limit >= amount {
		q.CreditAppliedSat = amount
		q.ArkFundingSat = 0
		return q
	}
	q.CreditAppliedSat = min(limit, amount-floor)
	q.ArkFundingSat = amount - q.CreditAppliedSat
	return q
}

// quoteSettlement describes the funding path a quote previews. The credit a
// payment uses includes its shortfall: the client tops that up before it
// pays, so a dust invoice with no credit yet still settles from credit.
// Direct same-Ark settlement applies only when no credit is involved and
// the receiver attaches none, so no treasury bridge is needed.
func quoteSettlement(amount uint64, quote *swaprpc.CreditQuote,
	sameArk bool) swaprpc.SettlementType {

	credit := quote.CreditAppliedSat + quote.CreditShortfallSat
	switch {
	case credit == amount:
		return swaprpc.SettlementType_SETTLEMENT_TYPE_CREDIT

	case credit > 0:
		return swaprpc.SettlementType_SETTLEMENT_TYPE_MIXED

	case sameArk:
		return swaprpc.SettlementType_SETTLEMENT_TYPE_IN_ARK

	default:
		return swaprpc.SettlementType_SETTLEMENT_TYPE_LIGHTNING
	}
}

// QuoteInSwap previews the same funding split used for admission without
// reserving credits or exposing any signing artifact.
// Invoice amounts must be whole satoshis on regtest. Accessing an account
// requires its request-bound authorization, whose nonce binding is persisted.
func (s *Server) QuoteInSwap(ctx context.Context,
	req *swaprpc.QuoteInSwapRequest) (*swaprpc.QuoteInSwapResponse, error) {

	invoice, amount, err := s.decodeInvoice(req.GetInvoice())
	if err != nil {
		return nil, err
	}

	// Read available credits under authorization and the state lock, then
	// use the same split calculation as admission without reserving the
	// result.
	var resp *swaprpc.QuoteInSwapResponse
	err = s.transact(ctx, func() error {
		var available uint64
		if len(req.AccountPubkey) > 0 {
			account, _, err := s.authorizeCredit(req)
			if err != nil {
				return err
			}
			a, err := s.account(account)
			if err != nil {
				return err
			}
			available = a.Finalized - a.Reserved
		} else if req.MaxCreditSat > 0 {
			return status.Error(
				codes.InvalidArgument,
				"credit account required",
			)
		}
		quote := s.creditQuote(amount, available, req.MaxCreditSat)
		local, err := s.sameArkInvoice(invoice, amount)
		if err != nil {
			return err
		}

		settlement := quoteSettlement(
			amount, quote, local != nil &&
				local.Response.AttachedCreditSat == 0,
		)
		resp = &swaprpc.QuoteInSwapResponse{PaymentHash: invoice.PaymentHash[:], InvoiceAmountSat: amount, AmountSat: quote.ArkFundingSat, SettlementType: settlement,
			Expiry: timestamppb.New(minTime(
				invoice.Timestamp.Add(invoice.Expiry()),
				s.cfg.Clock.Now().Add(swapLifetime),
			)), CreditQuote: quote}
		return nil
	})
	return resp, err
}

// minTime returns the earlier of two absolute operation deadlines.
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// swapPolicy reconstructs the public six-leaf vHTLC with independent swap
// participant and operator keys. hash must be 32 bytes and cfg non-nil.
// RefundLocktime is an absolute block height; unilateral delays are relative
// block counts from the negotiated terms.
func (s *Server) swapPolicy(sender, receiver *btcec.PublicKey, hash []byte,
	cfg *swaprpc.VHTLCConfig) (*arkscript.VHTLCPolicy, error) {

	if len(hash) != 32 || cfg == nil {
		return nil, errors.New("incomplete vHTLC terms")
	}
	return arkscript.NewVHTLCPolicy(
		arkscript.VHTLCOpts{Sender: sender, Receiver: receiver, Server: s.key.PubKey(), PreimageHash: lntypes.Hash(hash),
			RefundLocktime: cfg.RefundLocktime, UnilateralClaimDelay: cfg.UnilateralClaimDelay, UnilateralRefundDelay: cfg.UnilateralRefundDelay,
			UnilateralRefundWithoutReceiverDelay: cfg.UnilateralRefundWithoutReceiverDelay},
	)
}

// CreateInSwap admits one payment hash, reserves its credit share, and returns
// the immutable vHTLC terms. Credit-only calls wait for real LND settlement.
// The payment hash fixes invoice, client key, fee cap and credit cap across
// retries. Canceling a waiting credit-only RPC leaves the durable payment
// active; a later retry can recover its outcome.
func (s *Server) CreateInSwap(ctx context.Context,
	req *swaprpc.CreateInSwapRequest) (*swaprpc.CreateInSwapResponse,
	error) {

	// Fix invoice amount, network, expiry, and the sender key before
	// reserving credit or negotiating a conditional funding output.
	invoice, amount, err := s.decodeInvoice(req.GetInvoice())
	if err != nil {
		return nil, err
	}
	sender, err := btcec.ParsePubKey(req.ClientVhtlcPubkey)
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument, "client vHTLC key required",
		)
	}
	id := hex.EncodeToString(invoice.PaymentHash[:])
	var response *swaprpc.CreateInSwapResponse
	err = s.transact(ctx, func() error {
		account := ""
		if len(req.AccountPubkey) > 0 {
			var err error
			account, _, err = s.authorizeCredit(req)
			if err != nil {
				return err
			}
		} else if req.MaxCreditSat > 0 {
			return status.Error(
				codes.InvalidArgument,
				"credit account required",
			)
		}

		// A payment hash identifies one immutable attempt. Retrying may
		// recover its original terms but may not redirect funds or
		// alter the credit split.
		old, err := get[inSwap](s, "in-swap/"+id)
		if err != nil {
			return err
		}
		if old != nil {
			if old.Request.Invoice != req.Invoice || !bytes.Equal(
				old.Request.ClientVhtlcPubkey,
				req.ClientVhtlcPubkey,
			) || old.Account != account || old.Request.MaxCreditSat != req.MaxCreditSat || old.Request.MaxFeeSat != req.MaxFeeSat {

				return status.Error(
					codes.AlreadyExists,
					"payment hash already admitted with "+
						"different terms",
				)
			}
			response = old.Response
			return nil
		}

		// Compute and reserve against the same balance snapshot so
		// simultaneous payments cannot both consume the quoted
		// available credit.
		a, err := s.account(account)
		if err != nil {
			return err
		}
		quote := s.creditQuote(
			amount, a.Finalized-a.Reserved, req.MaxCreditSat,
		)
		if quote.CreditShortfallSat > 0 {
			return status.Error(
				codes.ResourceExhausted,
				"credit top-up required",
			)
		}

		// External payments use a server-owned claim key. A direct
		// same-Ark payment instead names the actual receiver, who alone
		// knows the preimage.
		receiver := s.deriveKey("swap-receiver/" + id)
		receiverPub := receiver.PubKey()
		local, err := s.sameArkInvoice(invoice, amount)
		if err != nil {
			return err
		}
		direct := local != nil && quote.CreditAppliedSat == 0 &&
			local.Response.AttachedCreditSat == 0
		if direct {
			if local.Phase != "registered" {
				return status.Error(
					codes.AlreadyExists,
					"receive already has a payer",
				)
			}
			receiverPub, err = btcec.ParsePubKey(
				local.Request.ClientVhtlcPubkey,
			)
			if err != nil {
				return err
			}
		}

		// Freeze absolute and relative refund terms at admission; the
		// saved policy must remain reconstructible when a payment
		// completes or fails later.
		cfg := &swaprpc.VHTLCConfig{RefundLocktime: s.height + swapRefundBlocks, UnilateralClaimDelay: s.cfg.ExitDelay,
			UnilateralRefundDelay: s.cfg.ExitDelay * 2, UnilateralRefundWithoutReceiverDelay: s.cfg.ExitDelay * 3, SwapserverPubkey: receiver.PubKey().SerializeCompressed()}
		response = &swaprpc.CreateInSwapResponse{PaymentHash: invoice.PaymentHash[:], AmountSat: quote.ArkFundingSat, ServerPubkey: receiverPub.SerializeCompressed(), VhtlcConfig: cfg,
			Expiry: timestamppb.New(minTime(
				invoice.Timestamp.Add(invoice.Expiry()),
				s.cfg.Clock.Now().Add(swapLifetime),
			)), SettlementType: swaprpc.SettlementType_SETTLEMENT_TYPE_LIGHTNING, CreditQuote: quote}
		r := &inSwap{
			Request:  req,
			Response: response,
			Account:  account,
			Phase: "awaiting-fu" +
				"nding",
		}
		r.InArk = direct
		r.Bridge = local != nil && !direct
		if direct {
			response.SettlementType = swaprpc.SettlementType_SETTLEMENT_TYPE_IN_ARK
			cfg.SwapserverPubkey = sender.SerializeCompressed()
		}

		// Reserve the credit share until an authoritative payment
		// outcome either consumes it or proves it safe to release.
		if quote.CreditAppliedSat > 0 {
			a.Reserved += quote.CreditAppliedSat
			if err := s.put(
				"credit-account/"+account, a,
			); err != nil {

				return err
			}
			response.SettlementType = swaprpc.SettlementType_SETTLEMENT_TYPE_MIXED
			now := timestamppb.New(s.cfg.Clock.Now())
			r.CreditID = "pay/" + id
			credit := &creditRecord{Account: account, Operation: &swaprpc.CreditOperation{OperationId: r.CreditID, Type: swaprpc.CreditOperationType_CREDIT_OPERATION_TYPE_PAY,
				State: swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_RESERVED, AmountSat: quote.CreditAppliedSat, PaymentHash: invoice.PaymentHash[:], Invoice: req.Invoice, CreatedAt: now, UpdatedAt: now}}
			if err := s.put(
				"credit-operation/"+r.CreditID, credit,
			); err != nil {

				return err
			}
		}

		// Credit-only payments can begin immediately. Other payments
		// must first receive an exact indexed vHTLC matching these
		// negotiated policy bytes.
		if quote.ArkFundingSat == 0 {
			response.SettlementType = swaprpc.SettlementType_SETTLEMENT_TYPE_CREDIT
			r.Phase = "paying"
		} else {
			policy, err := s.swapPolicy(
				sender, receiverPub, invoice.PaymentHash[:],
				cfg,
			)
			if err != nil {
				return err
			}
			r.Policy, err = policy.Template.Encode()
			if err != nil {
				return err
			}
			r.Script, err = policy.PkScript()
			if err != nil {
				return err
			}
		}
		if len(r.Policy) > 0 {
			if err := s.put(
				"known-policy/"+hex.EncodeToString(r.Script),
				r.Policy,
			); err != nil {

				return err
			}
		}

		// Bind local receiver state to this payer in the same
		// transaction. Credit-bearing transfers need separate treasury
		// funding, while direct transfers wait for the sender's own
		// conditional output.
		if r.Bridge {
			if local.Phase != "registered" {
				return status.Error(
					codes.AlreadyExists,
					"receive already has a payer",
				)
			}
			local.Phase = "awaiting-internal"
			local.Internal = true
			if err := s.put("out-swap/"+id, local); err != nil {
				return err
			}
		}
		if direct {
			local.Phase = "awaiting-sender"
			local.Config = cfg
			local.Policy = r.Policy
			local.Script = r.Script
			if err := s.put("out-swap/"+id, local); err != nil {
				return err
			}
		}
		return s.put("in-swap/"+id, r)
	})
	if err != nil {
		return nil, err
	}
	if response.SettlementType != swaprpc.SettlementType_SETTLEMENT_TYPE_CREDIT {
		return response, nil
	}

	// Credit-only callers need the settlement preimage in the RPC result.
	// Wait on committed state changes; cancellation does not cancel the
	// durable pay.
	for {
		s.mu.Lock()
		current, err := get[inSwap](s, "in-swap/"+id)
		wake := s.wake
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if current.Phase == "completed" {
			return current.Response, nil
		}
		if current.Phase == "failed" {
			return nil, status.Error(
				codes.FailedPrecondition, current.Failure,
			)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-wake:
		}
	}
}

// runSwaps owns blocking LND payment streams independently of mailbox delivery
// and chain polling, so receiving and claiming remain responsive during pays.
func (s *Server) runSwaps() {
	defer s.wg.Done()

	// Keep blocking payment streams off the mailbox and chain worker.
	// Shutdown cancels their parent context and joins this owned worker.
	for {
		select {
		case <-s.ctx.Done():
			return

		case <-s.cfg.Clock.TickAfter(workerInterval):
		}
		if err := s.pollInSwaps(s.ctx); err != nil {
			s.cfg.Log.Debug(
				"swap reconciliation pending", "error", err,
			)
		}
	}
}

// pollInSwaps binds exact indexed funding before permitting an LND payment and
// claims successful payments with their real preimage.
func (s *Server) pollInSwaps(ctx context.Context) error {
	// Snapshot unresolved attempts without retaining the lock across LND
	// streams; terminal failures must never become new routing attempts.
	s.mu.Lock()
	var ids []string
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "in-swap/") {
			continue
		}
		r, err := get[inSwap](s, key)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if r.Phase == "completed" || r.Phase == "failed" {
			continue
		}
		ids = append(ids, strings.TrimPrefix(key, "in-swap/"))
	}
	s.mu.Unlock()
	for _, id := range ids {
		err := s.transact(ctx, func() error {
			r, err := get[inSwap](s, "in-swap/"+id)
			if err != nil {
				return err
			}
			if r.Phase != "awaiting-funding" {
				return nil
			}

			// A funding notification can race the expiry worker.
			// Never begin a Lightning payment after its negotiated
			// admission deadline.
			if !s.cfg.Clock.Now().Before(
				r.Response.Expiry.AsTime(),
			) {

				return nil
			}

			// Recognize funding by live indexed value, script, and
			// policy together. A script match alone cannot
			// establish the negotiated payment amount.
			for key := range s.state.Records {
				if !strings.HasPrefix(key, "vtxo/") {
					continue
				}
				coin, err := get[vtxoRecord](s, key)
				if err != nil {
					return err
				}
				if coin.VTXO.Status == arkrpc.VTXOStatus_VTXO_STATUS_LIVE && coin.VTXO.ValueSat == r.Response.AmountSat && bytes.Equal(coin.Policy, r.Policy) && bytes.Equal(
					coin.VTXO.PkScript, r.Script,
				) {

					r.Outpoint = strings.TrimPrefix(
						key, "vtxo/",
					)
					r.Phase = "paying"

					// A direct payment already funds the
					// receiver's claim output; announce
					// that exact outpoint instead of
					// routing a Lightning payment back to
					// ourselves.
					if r.InArk {
						local, err := get[outSwap](
							s, "out-swap/"+id,
						)
						if err != nil {
							return err
						}
						if local == nil {
							return errors.New(
								"same-Ark " +
									"rece" +
									"iver " +
									"miss" +
									"ing",
							)
						}
						local.Outpoint = r.Outpoint
						local.Phase = "funded"
						if err := s.emitSwap(
							local,
							&swaprpc.SwapMailboxEvent{Event: &swaprpc.SwapMailboxEvent_InArkHtlc{InArkHtlc: &swaprpc.InArkHtlcEvent{
								PaymentHash: r.Response.PaymentHash, AmountSat: r.Response.AmountSat, SenderPubkey: r.Request.ClientVhtlcPubkey, VhtlcConfig: r.Response.VhtlcConfig, VhtlcOutpoint: r.Outpoint, VhtlcAmountSat: r.Response.AmountSat}}},
						); err != nil {

							return err
						}
						if err := s.put(
							"out-swap/"+id, local,
						); err != nil {

							return err
						}
						r.Phase = "in-ark"
					}

					return s.put("in-swap/"+id, r)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		s.mu.Lock()
		r, err := get[inSwap](s, "in-swap/"+id)
		s.mu.Unlock()
		if err != nil {
			return err
		}

		// Same-Ark completion is proven by the receiver's finalized
		// claim witness, not by an unverified preimage message.
		if r.Phase == "in-ark" {
			if err := s.transact(ctx, func() error {
				current, err := get[inSwap](s, "in-swap/"+id)
				if err != nil {
					return err
				}
				preimage, err := s.observedPreimage(
					current.Outpoint,
					current.Response.PaymentHash,
				)
				if err != nil {
					return err
				}
				if len(
					preimage,
				) > 0 {

					current.Preimage = preimage
					current.Phase = "completed"
					return s.put("in-swap/"+id, current)
				}
				return nil
			}); err != nil {

				return err
			}
		}

		// Resolve payment outside the state lock, then commit only if
		// the saved attempt is still paying. Transient RPC errors leave
		// it recoverable.
		if r.Phase == "paying" {
			var payment *lnrpc.Payment
			var err error
			if r.Bridge {
				payment, err = s.payInternal(ctx, id)
			} else {
				payment, err = s.payInvoice(ctx, r)
			}
			if err != nil {
				return err
			}
			err = s.transact(ctx, func() error {
				current, err := get[inSwap](s, "in-swap/"+id)
				if err != nil {
					return err
				}
				if current.Phase != "paying" {
					return nil
				}

				// Check the disclosed secret against the
				// negotiated hash before authorizing the
				// treasury claim or returning credit-only
				// success.
				if payment.Status == lnrpc.Payment_SUCCEEDED {
					preimage, err := hex.DecodeString(
						payment.PaymentPreimage,
					)
					if err != nil || len(
						preimage,
					) != 32 {

						return errors.New(
							"LND returned invalid " +
								"preimage",
						)
					}
					hash := sha256.Sum256(preimage)
					if !bytes.Equal(
						hash[:],
						current.Response.PaymentHash,
					) {

						return errors.New(
							"LND preimage hash " +
								"mismatch",
						)
					}
					current.Preimage = preimage
					current.Phase = "claiming"
					if current.Response.AmountSat == 0 {
						current.Phase = "completed"
						current.Response.Preimage = preimage
					}
				} else if payment.Status == lnrpc.Payment_FAILED {
					current.Phase = "failed"
					current.Failure = payment.FailureReason.String()
				} else {
					return nil
				}

				// The terminal routing outcome determines the
				// ledger movement: failed payments release
				// reserved value, successful ones consume it
				// exactly once.
				if current.CreditID != "" {
					credit, err := get[creditRecord](
						s,
						"credit-operation/"+current.CreditID,
					)
					if err != nil {
						return err
					}
					if current.Phase == "failed" {
						a, err := s.account(
							current.Account,
						)
						if err != nil {
							return err
						}
						if a.Reserved < credit.Operation.AmountSat {
							return errors.New(
								"missing " +
									"cred" +
									"it " +
									"rese" +
									"rvat" +
									"ion",
							)
						}
						a.Reserved -= credit.Operation.AmountSat
						if err := s.put(
							"credit-account/"+current.Account,
							a,
						); err != nil {

							return err
						}
						credit.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_RELEASED
						credit.Operation.LastError = current.Failure
					} else {
						if err := s.postCredit(
							credit, "debit",
							credit.Operation.AmountSat,
						); err != nil {

							return err
						}
						credit.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_DEBITED
					}
					credit.Operation.CompletedAt = timestamppb.New(s.cfg.Clock.Now())
					credit.Operation.UpdatedAt = credit.Operation.CompletedAt
					if err := s.put(
						"credit-operation/"+current.CreditID,
						credit,
					); err != nil {

						return err
					}
				}
				return s.put("in-swap/"+id, current)
			})
			if err != nil {
				return err
			}
		}

		// After successful payment, materialize a real claim using the
		// verified preimage and original vHTLC terms before marking the
		// swap complete.
		if err := s.transact(ctx, func() error {
			current, err := get[inSwap](s, "in-swap/"+id)
			if err != nil {
				return err
			}
			if current.Phase != "claiming" {
				return nil
			}
			coin, err := get[vtxoRecord](
				s, "vtxo/"+current.Outpoint,
			)
			if err != nil {
				return err
			}
			if coin == nil {
				return errors.New("funded swap input missing")
			}
			sender, err := btcec.ParsePubKey(
				current.Request.ClientVhtlcPubkey,
			)
			if err != nil {
				return err
			}
			receiver := s.deriveKey("swap-receiver/" + id)
			policy, err := s.swapPolicy(
				sender, receiver.PubKey(),
				current.Response.PaymentHash,
				current.Response.VhtlcConfig,
			)
			if err != nil {
				return err
			}
			path, err := policy.ClaimPath(lntypes.Preimage(
				current.Preimage,
			))
			if err != nil {
				return err
			}
			current.ClaimSession, err = s.spendOwnedVTXO(
				ctx, coin, receiver, path,
			)
			if err != nil {
				return err
			}
			current.Phase = "completed"
			return s.put("in-swap/"+id, current)
		}); err != nil {

			return err
		}
	}
	return nil
}

// payInvoice resumes a persisted LND payment by hash before considering a new
// attempt. A terminal failure remains terminal so cooperative refunds are safe.
// The caller must have durably entered paying and must not hold s.mu.
// Transport errors leave the result ambiguous and must not authorize a refund.
func (s *Server) payInvoice(ctx context.Context, r *inSwap) (*lnrpc.Payment,
	error) {

	ctx, cancel := context.WithTimeout(
		ctx, paymentTimeout+backend.RPCTimeout,
	)
	defer cancel()

	// A previous call may have paid before losing its RPC response. Query
	// LND's durable payment history first so recovery cannot pay the
	// invoice twice.
	stream, err := s.cfg.LND.Router.TrackPaymentV2(
		ctx, &routerrpc.TrackPaymentRequest{
			PaymentHash:       r.Response.PaymentHash,
			NoInflightUpdates: true,
		},
	)
	if err == nil {
		payment, recvErr := stream.Recv()
		if recvErr == nil {
			return payment, nil
		}
		err = recvErr
	}

	// Only an authoritative absence allows a new attempt. A terminal failed
	// payment returned above stays failed so refund signatures remain safe.
	if status.Code(err) != codes.NotFound {
		return nil, err
	}
	fee := int64(r.Request.MaxFeeSat)
	if fee == 0 {
		fee = 1000
	}
	send, err := s.cfg.LND.Router.SendPaymentV2(
		ctx, &routerrpc.SendPaymentRequest{
			PaymentRequest:    r.Request.Invoice,
			FeeLimitSat:       fee,
			TimeoutSeconds:    int32(paymentTimeout / time.Second),
			NoInflightUpdates: true,
			MaxParts:          1,
		},
	)
	if err != nil {
		return nil, err
	}
	payment, err := send.Recv()
	if err != nil {
		return nil, fmt.Errorf("await LND payment: %w", err)
	}
	return payment, nil
}

// sameArkInvoice recognizes the registered payment hash, virtual channel and
// amount. The invoice signer is payment-scoped and intentionally differs from
// the authenticated vHTLC participant key; only the receiver knows its
// preimage.
func (s *Server) sameArkInvoice(invoice *zpay32.Invoice,
	amount uint64) (*outSwap, error) {

	id := hex.EncodeToString(invoice.PaymentHash[:])
	r, err := get[outSwap](s, "out-swap/"+id)
	if err != nil || r == nil {
		return nil, err
	}

	// Match the registered virtual channel as well as hash and amount; a
	// local hash by itself does not establish that this invoice uses our
	// receive route.
	matched := false
	for _, route := range invoice.RouteHints {
		if len(route) > 0 &&
			route[len(route)-1].ChannelID == r.ChannelID {

			matched = true
		}
	}
	if amount != r.Request.AmountSat || !matched {

		return nil, status.Error(
			codes.InvalidArgument,
			"invoice differs from registered receive",
		)
	}
	if s.cfg.Clock.Now().Unix() >= r.Expires {
		return nil, status.Error(
			codes.FailedPrecondition, "receive route expired",
		)
	}
	return r, nil
}

// payInternal bridges a credit-bearing same-Ark invoice through a real
// treasury-funded receiver vHTLC. Its claim preimage then settles the payer's
// credit reservation and, for mixed payments, its separate funded vHTLC.
func (s *Server) payInternal(ctx context.Context, id string) (*lnrpc.Payment,
	error) {

	// Create receiver funding once under the state lock. Later polls report
	// its saved outcome while the ordinary receive worker observes the
	// claim.
	err := s.transact(ctx, func() error {
		r, err := get[outSwap](s, "out-swap/"+id)
		if err != nil {
			return err
		}
		if r == nil || !r.Internal {
			return errors.New("internal receive missing")
		}
		if r.Phase != "awaiting-internal" {
			return nil
		}

		// A credit-bearing local payment uses a treasury sender key,
		// separating the receiver's conditional funds from the payer's
		// credit or vHTLC contribution.
		sender := s.deriveKey("swap-sender/" + id)
		receiver, err := btcec.ParsePubKey(r.Request.ClientVhtlcPubkey)
		if err != nil {
			return err
		}
		r.Config = &swaprpc.VHTLCConfig{RefundLocktime: s.height + swapRefundBlocks, UnilateralClaimDelay: s.cfg.ExitDelay, UnilateralRefundDelay: 2 * s.cfg.ExitDelay,
			UnilateralRefundWithoutReceiverDelay: 3 * s.cfg.ExitDelay, SwapserverPubkey: sender.PubKey().SerializeCompressed()}
		policy, err := s.swapPolicy(
			sender.PubKey(), receiver, r.Request.PaymentHash,
			r.Config,
		)
		if err != nil {
			return err
		}
		r.Policy, err = policy.Template.Encode()
		if err != nil {
			return err
		}
		r.Script, err = policy.PkScript()
		if err != nil {
			return err
		}
		if err := s.put(
			"known-policy/"+hex.EncodeToString(r.Script), r.Policy,
		); err != nil {

			return err
		}
		event := &swaprpc.InArkHtlcEvent{
			PaymentHash:  r.Request.PaymentHash,
			AmountSat:    r.Response.VhtlcAmountSat,
			SenderPubkey: sender.PubKey().SerializeCompressed(),
			VhtlcConfig:  r.Config,
		}

		// Attached receiver credits require consent to the combined
		// terms before funding. Without attached credits the treasury
		// can issue the output immediately.
		if r.Response.AttachedCreditSat > 0 {
			event.RequestedAmountSat = r.Request.AmountSat
			event.AttachedCreditSat = r.Response.AttachedCreditSat
			r.Phase = "awaiting-ack"
		} else {
			funding, err := s.fundInventoryOutput(
				ctx, r.Policy, r.Response.VhtlcAmountSat,
			)
			if err != nil {
				return err
			}
			r.Session = funding.Session
			r.Outpoint = funding.Outpoint.String()
			r.Phase = "funded"
			event.VhtlcOutpoint = r.Outpoint
			event.VhtlcAmountSat = r.Response.VhtlcAmountSat
		}
		if err := s.emitSwap(r, &swaprpc.SwapMailboxEvent{
			Event: &swaprpc.SwapMailboxEvent_InArkHtlc{
				InArkHtlc: event,
			},
		}); err != nil {

			return err
		}
		return s.put("out-swap/"+id, r)
	})
	if err != nil {
		return nil, err
	}

	// Translate durable receive state into the payment outcome consumed by
	// the payer worker; the preimage still comes only from a verified
	// claim.
	s.mu.Lock()
	r, err := get[outSwap](s, "out-swap/"+id)
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if r.Phase == "completed" {
		return &lnrpc.Payment{
			Status:          lnrpc.Payment_SUCCEEDED,
			PaymentPreimage: hex.EncodeToString(r.Preimage),
		}, nil
	}
	if r.Phase == "failed" {
		return &lnrpc.Payment{
			Status:        lnrpc.Payment_FAILED,
			FailureReason: lnrpc.PaymentFailureReason_FAILURE_REASON_CANCELED,
		}, nil
	}
	return &lnrpc.Payment{Status: lnrpc.Payment_IN_FLIGHT}, nil
}
