package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/google/uuid"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// creditInvoiceLifetime bounds the funding interval of an account
	// operation.
	creditInvoiceLifetime = time.Hour
)

// creditAccount is a durable ledger with reservations separate from finalized
// value. Operations never derive balances from client supplied amounts alone.
type creditAccount struct {
	Finalized uint64
	Reserved  uint64
	Ledger    []*swaprpc.CreditLedgerEntry
}

// creditRecord retains request identity, public operation history and funding
// evidence. Lightning preimages are deterministically derived and never listed.
type creditRecord struct {
	Account   string
	Digest    []byte
	Operation *swaprpc.CreditOperation
	Funding   *swaprpc.CreateCreditResponse
	Source    swaprpc.CreditFundingSource
	Memo      string
}

// authorizeCredit verifies the upstream request-bound signature and commits its
// nonce binding with the operation. An exact signed retry is safe; reuse for a
// different request is rejected even when it carries a fresh valid signature.
func (s *Server) authorizeCredit(req proto.Message) (string, []byte, error) {
	digest, keyRaw, err := swaprpc.CreditAccountRequestDigest(req)
	if err != nil {
		return "", nil, status.Error(codes.InvalidArgument, err.Error())
	}
	auth, err := swaprpc.CreditAccountAuthorizationForRequest(req)
	if err != nil {
		return "", nil, err
	}
	key, err := btcec.ParsePubKey(keyRaw)
	if err != nil || len(keyRaw) != 33 || auth == nil ||
		len(auth.Nonce) != 32 || len(auth.Signature) != 64 {

		return "", nil, status.Error(
			codes.Unauthenticated,
			"credit account authorization required",
		)
	}
	now := s.cfg.Clock.Now().Unix()
	if auth.ExpiresAtUnix <= now || auth.ExpiresAtUnix > now+int64(
		swaprpc.CreditAccountMaxAuthTTL/time.Second,
	) {

		return "", nil, status.Error(
			codes.Unauthenticated,
			"credit authorization expired or too long",
		)
	}
	signed := swaprpc.CreditAccountAuthDigest(
		keyRaw, digest, auth.ExpiresAtUnix, auth.Nonce,
	)
	sig, err := schnorr.ParseSignature(auth.Signature)
	if err != nil || !sig.Verify(
		signed[:], key,
	) {

		return "", nil, status.Error(
			codes.Unauthenticated, "invalid credit authorization",
		)
	}
	account := hex.EncodeToString(keyRaw)
	nonceKey := "credit-nonce/" + account + "/" +
		hex.EncodeToString(auth.Nonce)
	previous, err := get[[]byte](s, nonceKey)
	if err != nil {
		return "", nil, err
	}
	if previous != nil && !bytes.Equal(
		*previous, signed[:],
	) {

		return "", nil, status.Error(
			codes.AlreadyExists, "credit nonce reused",
		)
	}
	if err := s.put(nonceKey, signed[:]); err != nil {
		return "", nil, err
	}
	return account, digest[:], nil
}

// account retrieves the ledger, creating an empty value only for new accounts.
func (s *Server) account(id string) (*creditAccount, error) {
	a, err := get[creditAccount](s, "credit-account/"+id)
	if err != nil {
		return nil, err
	}
	if a == nil {
		a = &creditAccount{}
	}
	if a.Reserved > a.Finalized {
		return nil, errors.New("credit reservations exceed ledger")
	}
	return a, nil
}

// creditIntentKey namespaces caller idempotency keys by account and hashes
// their bounded input so user delimiters cannot collide with another account.
func creditIntentKey(account, key string) (string, error) {
	if key == "" || len(
		key,
	) > 256 {

		return "", status.Error(
			codes.InvalidArgument,
			"bounded idempotency key required",
		)
	}
	digest := sha256.Sum256([]byte(key))
	return "credit-intent/" + account + "/" + hex.EncodeToString(
		digest[:],
	), nil
}

// CreateCredit records a funding intent before creating its real LND invoice
// or returning a dedicated Ark destination. Retrying resumes the same intent.
func (s *Server) CreateCredit(ctx context.Context,
	req *swaprpc.CreateCreditRequest) (*swaprpc.CreateCreditResponse,
	error) {

	var operation string
	err := s.transact(ctx, func() error {
		account, digest, err := s.authorizeCredit(req)
		if err != nil {
			return err
		}
		key, err := creditIntentKey(account, req.IdempotencyKey)
		if err != nil {
			return err
		}
		if req.AmountSat == 0 || req.AmountSat > btcutil.MaxSatoshi ||
			len(req.Memo) > 500 {

			return status.Error(
				codes.InvalidArgument,
				"invalid credit funding amount or memo",
			)
		}
		if req.Source != swaprpc.CreditFundingSource_CREDIT_FUNDING_SOURCE_LIGHTNING_RECEIVE && req.Source != swaprpc.CreditFundingSource_CREDIT_FUNDING_SOURCE_ARK_TOPUP {
			return status.Error(
				codes.InvalidArgument,
				"credit funding source required",
			)
		}
		if req.Source == swaprpc.CreditFundingSource_CREDIT_FUNDING_SOURCE_ARK_TOPUP &&
			req.AmountSat < uint64(s.cfg.MinAmount) {

			return status.Error(
				codes.InvalidArgument,
				"Ark top-up below minimum",
			)
		}
		old, err := get[string](s, key)
		if err != nil {
			return err
		}
		if old != nil {
			r, err := get[creditRecord](s, "credit-operation/"+*old)
			if err != nil {
				return err
			}
			if r == nil || !bytes.Equal(
				r.Digest, digest,
			) {

				return status.Error(
					codes.AlreadyExists,
					"credit intent changed",
				)
			}
			operation = *old
			return nil
		}
		operation = uuid.NewString()
		now := s.cfg.Clock.Now()
		r := &creditRecord{Account: account, Digest: digest, Source: req.Source, Memo: req.Memo,
			Operation: &swaprpc.CreditOperation{OperationId: operation, Type: swaprpc.CreditOperationType_CREDIT_OPERATION_TYPE_FUNDING,
				State: swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_CREATED, AmountSat: req.AmountSat, CreatedAt: timestamppb.New(now), UpdatedAt: timestamppb.New(now)},
			Funding: &swaprpc.CreateCreditResponse{
				OperationId: operation,
				State:       swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_CREATED,
				AmountSat:   req.AmountSat,
				ExpiresAt: timestamppb.New(now.Add(
					creditInvoiceLifetime,
				)),
			}}
		if req.Source == swaprpc.CreditFundingSource_CREDIT_FUNDING_SOURCE_ARK_TOPUP {
			domain := "credit-topup/" + operation
			pub := s.deriveKey(domain).PubKey()
			policy, err := arkscript.StandardVTXOTemplate(
				pub, s.key.PubKey(), s.cfg.ExitDelay,
			)
			if err != nil {
				return err
			}
			script, err := policy.PkScript()
			if err != nil {
				return err
			}
			if err := s.put(
				"inventory-script/"+hex.EncodeToString(script),
				domain,
			); err != nil {

				return err
			}
			r.Funding.DestinationPubkey = schnorr.SerializePubKey(
				pub,
			)
			r.Operation.DestinationPubkey = r.Funding.DestinationPubkey
			r.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_AWAITING_PAYMENT
			r.Funding.State = r.Operation.State
		} else {
			preimage := s.deriveKey(
				"credit-invoice/" + operation,
			).Serialize()
			hash := sha256.Sum256(preimage)
			r.Funding.PaymentHash = hash[:]
			r.Operation.PaymentHash = hash[:]
		}
		if err := s.put("credit-operation/"+operation, r); err != nil {
			return err
		}
		return s.put(key, operation)
	})
	if err != nil {
		return nil, err
	}
	if err := s.pollCreditOperation(ctx, operation); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := get[creditRecord](s, "credit-operation/"+operation)
	if err != nil {
		return nil, err
	}
	return r.Funding, nil
}

// postCredit records one irreversible ledger movement under an operation ID.
// The caller must change the operation state in the same transaction.
func (s *Server) postCredit(r *creditRecord, direction string,
	amount uint64) error {

	a, err := s.account(r.Account)
	if err != nil {
		return err
	}
	for _, entry := range a.Ledger {
		if entry.OperationId == r.Operation.OperationId &&
			entry.Direction == direction {

			if entry.AmountSat != amount {
				return errors.New(
					"credit ledger replay changed amount",
				)
			}
			return nil
		}
	}
	switch direction {
	case "credit":
		if amount > btcutil.MaxSatoshi-a.Finalized {
			return errors.New("credit balance overflow")
		}
		a.Finalized += amount

	case "debit":
		if a.Reserved < amount || a.Finalized < amount {
			return errors.New("credit debit exceeds reservation")
		}
		a.Finalized -= amount
		a.Reserved -= amount

	default:
		return errors.New("unknown credit ledger direction")
	}
	a.Ledger = append(a.Ledger, &swaprpc.CreditLedgerEntry{
		EntryId:     uuid.NewString(),
		OperationId: r.Operation.OperationId,
		Direction:   direction,
		AmountSat:   amount,
		CreatedAt:   timestamppb.New(s.cfg.Clock.Now()),
	})
	return s.put("credit-account/"+r.Account, a)
}

// ListCredits returns authenticated balances and bounded recent history. It
// never reveals invoice preimages or another account's operations.
func (s *Server) ListCredits(ctx context.Context,
	req *swaprpc.ListCreditsRequest) (*swaprpc.ListCreditsResponse, error) {

	var resp *swaprpc.ListCreditsResponse
	err := s.transact(ctx, func() error {
		account, _, err := s.authorizeCredit(req)
		if err != nil {
			return err
		}
		if req.Limit > 1000 {
			return status.Error(
				codes.InvalidArgument,
				"credit history limit exceeds 1000",
			)
		}
		limit := int(req.Limit)
		if limit == 0 {
			limit = 100
		}
		a, err := s.account(account)
		if err != nil {
			return err
		}
		resp = &swaprpc.ListCreditsResponse{
			FinalizedSat: a.Finalized,
			ReservedSat:  a.Reserved,
			AvailableSat: a.Finalized - a.Reserved,
		}
		for key := range s.state.Records {
			if !strings.HasPrefix(key, "credit-operation/") {
				continue
			}
			r, err := get[creditRecord](s, key)
			if err != nil {
				return err
			}
			if r.Account == account {
				resp.Operations = append(
					resp.Operations, r.Operation,
				)
			}
		}
		sort.Slice(resp.Operations, func(i, j int) bool {
			return resp.Operations[i].CreatedAt.AsTime().After(
				resp.Operations[j].CreatedAt.AsTime(),
			)
		})
		if len(resp.Operations) > limit {
			resp.Operations = resp.Operations[:limit]
		}
		for i := len(
			a.Ledger,
		) - 1; i >= 0 && len(
			resp.LedgerEntries,
		) < limit; i-- {

			resp.LedgerEntries = append(
				resp.LedgerEntries, a.Ledger[i],
			)
		}
		return nil
	})
	return resp, err
}

// pollCredits reconciles external funding independently of client retries.
func (s *Server) pollCredits(ctx context.Context) error {
	s.mu.Lock()
	var ids []string
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "credit-operation/") {
			continue
		}
		r, err := get[creditRecord](s, key)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if r.Funding == nil || (r.Operation.State != swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_CREATED && r.Operation.State != swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_AWAITING_PAYMENT) {
			continue
		}
		ids = append(ids, strings.TrimPrefix(key, "credit-operation/"))
	}
	s.mu.Unlock()
	for _, id := range ids {
		if err := s.pollCreditOperation(ctx, id); err != nil {
			return err
		}
	}
	return nil
}

// pollCreditOperation reconciles an invoice by its known hash across crashes,
// or credits an exact, finalized OOR top-up belonging to its dedicated key.
func (s *Server) pollCreditOperation(ctx context.Context, id string) error {
	ctx, cancel := context.WithTimeout(ctx, backend.RPCTimeout)
	defer cancel()
	s.mu.Lock()
	r, err := get[creditRecord](s, "credit-operation/"+id)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	if r == nil || r.Funding == nil || r.Operation.State == swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_CREDITED || r.Operation.State == swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_EXPIRED {
		return nil
	}
	var invoice *lnrpc.Invoice
	if r.Source == swaprpc.CreditFundingSource_CREDIT_FUNDING_SOURCE_LIGHTNING_RECEIVE {
		invoice, err = s.cfg.LND.Lightning.LookupInvoice(
			ctx, &lnrpc.PaymentHash{
				RHash: r.Operation.PaymentHash,
			},
		)
		if status.Code(err) == codes.NotFound || err != nil &&
			(strings.Contains(
				err.Error(), "unable to locate invoice",
			) || strings.Contains(
				err.Error(), "there are no existing "+
					"invoices",
			)) {

			_, addErr := s.cfg.LND.Lightning.AddInvoice(
				ctx, &lnrpc.Invoice{
					RPreimage: s.deriveKey(
						"credit-invoice/" + id,
					).Serialize(),
					Value: int64(r.Operation.AmountSat),
					Memo:  r.Memo,
					Expiry: int64(
						creditInvoiceLifetime / time.Second,
					),
				},
			)

			// RPC and background reconciliation may race to create
			// the same hash. The authoritative lookup resolves
			// duplicate and ambiguous AddInvoice errors without
			// minting another invoice or a second ledger entry.
			invoice, err = s.cfg.LND.Lightning.LookupInvoice(
				ctx, &lnrpc.PaymentHash{
					RHash: r.Operation.PaymentHash,
				},
			)
			if err != nil {
				return errors.Join(addErr, err)
			}
		}

		if err != nil {
			return err
		}
	}
	return s.transact(ctx, func() error {
		current, err := get[creditRecord](s, "credit-operation/"+id)
		if err != nil {
			return err
		}
		if current.Operation.State == swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_CREDITED {
			return nil
		}
		oldState, oldInvoice := current.Operation.State, current.Operation.Invoice
		funded := false
		if invoice != nil {
			if invoice.Value != int64(
				current.Operation.AmountSat,
			) || !bytes.Equal(
				invoice.RHash,
				current.Operation.PaymentHash,
			) {

				return errors.New("credit invoice mismatch")
			}
			current.Funding.Invoice = invoice.PaymentRequest
			current.Operation.Invoice = invoice.PaymentRequest
			current.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_AWAITING_PAYMENT
			funded = invoice.State == lnrpc.Invoice_SETTLED && invoice.AmtPaidSat >= int64(
				current.Operation.AmountSat,
			)
			if invoice.State == lnrpc.Invoice_CANCELED {
				current.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_EXPIRED
			}
		} else {
			policy, err := arkscript.StandardVTXOTemplate(
				s.deriveKey("credit-topup/"+id).PubKey(),
				s.key.PubKey(), s.cfg.ExitDelay,
			)
			if err != nil {
				return err
			}
			script, err := policy.PkScript()
			if err != nil {
				return err
			}
			for key := range s.state.Records {
				if !strings.HasPrefix(key, "vtxo/") {
					continue
				}
				v, err := get[vtxoRecord](s, key)
				if err != nil {
					return err
				}
				if bytes.Equal(
					v.VTXO.PkScript, script,
				) && v.VTXO.ValueSat == current.Operation.AmountSat {

					funded = true
					break
				}
			}
		}
		if funded {
			if err := s.postCredit(
				current, "credit", current.Operation.AmountSat,
			); err != nil {

				return err
			}
			current.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_CREDITED
			current.Operation.CompletedAt = timestamppb.New(
				s.cfg.Clock.Now(),
			)
		}
		if oldState == current.Operation.State &&
			oldInvoice == current.Operation.Invoice {

			return nil
		}
		current.Funding.State = current.Operation.State
		current.Operation.UpdatedAt = timestamppb.New(s.cfg.Clock.Now())
		return s.put("credit-operation/"+id, current)
	})
}

// RedeemCredit reserves credits and finalizes their real OOR transfer in one
// durable transaction. Insufficient inventory leaves the account unchanged.
func (s *Server) RedeemCredit(ctx context.Context,
	req *swaprpc.RedeemCreditRequest) (*swaprpc.RedeemCreditResponse,
	error) {

	var resp *swaprpc.RedeemCreditResponse
	err := s.transact(ctx, func() error {
		account, digest, err := s.authorizeCredit(req)
		if err != nil {
			return err
		}
		key, err := creditIntentKey(account, req.IdempotencyKey)
		if err != nil {
			return err
		}
		if req.AmountSat < uint64(s.cfg.MinAmount) ||
			req.AmountSat > btcutil.MaxSatoshi {

			return status.Error(
				codes.InvalidArgument,
				"redemption below minimum or above maximum",
			)
		}
		pub, err := schnorr.ParsePubKey(req.DestinationPubkey)
		if err != nil {
			return status.Error(
				codes.InvalidArgument,
				"x-only redemption destination required",
			)
		}
		old, err := get[string](s, key)
		if err != nil {
			return err
		}
		if old != nil {
			r, err := get[creditRecord](s, "credit-operation/"+*old)
			if err != nil {
				return err
			}
			if r == nil || !bytes.Equal(
				digest, r.Digest,
			) {

				return status.Error(
					codes.AlreadyExists,
					"credit intent changed",
				)
			}
			resp = &swaprpc.RedeemCreditResponse{
				OperationId: *old,
				State:       r.Operation.State,
				DebitedSat:  r.Operation.AmountSat,
				RedeemedSat: r.Operation.AmountSat,
				SessionId:   r.Operation.SessionId,
			}
			return nil
		}
		a, err := s.account(account)
		if err != nil {
			return err
		}
		if a.Finalized-a.Reserved < req.AmountSat {
			return status.Error(
				codes.ResourceExhausted,
				"insufficient available credit",
			)
		}
		a.Reserved += req.AmountSat
		if err := s.put("credit-account/"+account, a); err != nil {
			return err
		}
		policy, err := arkscript.StandardVTXOTemplate(
			pub, s.key.PubKey(), s.cfg.ExitDelay,
		)
		if err != nil {
			return err
		}
		raw, err := policy.Encode()
		if err != nil {
			return err
		}
		funding, err := s.fundInventoryOutput(ctx, raw, req.AmountSat)
		if err != nil {
			return err
		}
		now := timestamppb.New(s.cfg.Clock.Now())
		id := uuid.NewString()
		r := &creditRecord{Account: account, Digest: digest, Operation: &swaprpc.CreditOperation{OperationId: id, Type: swaprpc.CreditOperationType_CREDIT_OPERATION_TYPE_REDEMPTION,
			State: swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_REDEEMED, AmountSat: req.AmountSat, DestinationPubkey: req.DestinationPubkey, SessionId: funding.Session, CreatedAt: now, UpdatedAt: now, CompletedAt: now}}
		if err := s.postCredit(r, "debit", req.AmountSat); err != nil {
			return err
		}
		if err := s.put("credit-operation/"+id, r); err != nil {
			return err
		}
		if err := s.put(key, id); err != nil {
			return err
		}
		resp = &swaprpc.RedeemCreditResponse{
			OperationId: id,
			State:       r.Operation.State,
			DebitedSat:  req.AmountSat,
			RedeemedSat: req.AmountSat,
			SessionId:   funding.Session,
		}
		return nil
	})
	return resp, err
}
