package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/tx/psbtutil"
	"github.com/lightninglabs/wavelength/serverconn"
	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	// receiveRouteDelta leaves room for Ark ancestry and unilateral
	// recovery.
	receiveRouteDelta = 288

	// receiveSafetyMargin keeps the Ark refund before LND's auto-fail
	// deadline.
	receiveSafetyMargin = 36

	// maxReceiveParts bounds held multipart payment state for one invoice.
	maxReceiveParts = 64
)

// outSwap tracks a Lightning-to-Ark receive from the wallet's perspective.
// registered and collecting precede complete HTLC terms; awaiting-ack and
// acknowledged separate receiver consent from treasury funding. Once funded,
// the receive needs a verified claim or refund before becoming terminal.
// Circuits retain the virtual SCID's held shards for reconnect recovery.
type outSwap struct {
	Request   *swaprpc.RequestChannelIdRequest
	Response  *swaprpc.RequestChannelIdResponse
	Digest    []byte
	Account   string
	CreditID  string
	ChannelID uint64
	Expires   int64
	Phase     string
	Circuits  map[string]*routerrpc.ForwardHtlcInterceptRequest
	Config    *swaprpc.VHTLCConfig
	Policy    []byte
	Script    []byte
	Session   string
	Outpoint  string
	Preimage  []byte
	Ack       []byte
	Internal  bool
}

// RequestChannelId returns the funded node's virtual-hop route hint and binds
// it to this payment hash. Credits are reserved only after account proof.
// The request requires a signed account authorization, positive satoshis, a
// 32-byte hash and expiry in seconds, at most one day. The interceptor must be
// connected; exact retries return the original route and reservation.
func (s *Server) RequestChannelId(ctx context.Context, req *swaprpc.RequestChannelIdRequest) (*swaprpc.RequestChannelIdResponse, error) {
	// Authorize the receive terms and reserve any credit contribution in
	// one transaction before exposing a route that can accept real HTLCs.
	var response *swaprpc.RequestChannelIdResponse
	err := s.transact(ctx, func() error {
		account, digest, err := s.authorizeCredit(req)
		if err != nil {
			return err
		}
		if len(req.PaymentHash) != 32 || req.AmountSat == 0 ||
			req.AmountSat > btcutil.MaxSatoshi ||
			req.ExpirySeconds == 0 || req.ExpirySeconds > 86400 {

			return status.Error(
				codes.InvalidArgument,
				"invalid receive amount, hash or expiry",
			)
		}
		if !s.interceptorReady {
			return status.Error(
				codes.Unavailable,
				"Lightning interceptor not connected",
			)
		}
		id := hex.EncodeToString(req.PaymentHash)

		// A payment hash gets one route and immutable set of terms;
		// retries recover that route without reserving the receiver's
		// credits again.
		old, err := get[outSwap](s, "out-swap/"+id)
		if err != nil {
			return err
		}
		if old != nil {
			if !bytes.Equal(old.Digest, digest) {
				return status.Error(
					codes.AlreadyExists,
					"receive terms changed",
				)
			}
			response = old.Response
			return nil
		}

		// Below-minimum receives need attached credits to make a
		// spendable vHTLC. Reserve only the difference, leaving the
		// invoice amount unchanged.
		a, err := s.account(account)
		if err != nil {
			return err
		}
		available := a.Finalized - a.Reserved
		attached := uint64(0)
		if req.AmountSat < uint64(s.cfg.MinAmount) {
			attached = uint64(s.cfg.MinAmount) - req.AmountSat
			if !req.SupportsInArkCredit || attached > available {
				return status.Error(
					codes.ResourceExhausted,
					"small receive requires credit "+
						"funding or attached credits",
				)
			}
		}

		// Derive a stable virtual SCID from the hash for restart
		// recovery, while rejecting the unlikely collision rather than
		// routing two intents to one ID.
		hash := sha256.Sum256(append(
			[]byte("wavelength-regtest/scid/"), req.PaymentHash...,
		))
		channel := binary.BigEndian.Uint64(hash[:8]) | uint64(1)<<63
		collision, err := get[string](s, fmt.Sprintf(
			"virtual-channel/%d", channel,
		))
		if err != nil {
			return err
		}
		if collision != nil {
			return status.Error(
				codes.AlreadyExists,
				"virtual channel collision",
			)
		}
		response = &swaprpc.RequestChannelIdResponse{RequestedAmountSat: req.AmountSat, AvailableCreditSat: available, AttachedCreditSat: attached,
			VhtlcAmountSat: req.AmountSat + attached, DustLimitSat: uint64(
				s.cfg.MinAmount,
			), SettlementType: swaprpc.SettlementType_SETTLEMENT_TYPE_LIGHTNING,
			RouteHintPaths: []*swaprpc.RouteHintPath{
				{
					Hops: []*swaprpc.RouteHint{
						{
							NodeId:          s.lndPubkey,
							ChannelId:       channel,
							CltvExpiryDelta: receiveRouteDelta,
						},
					},
				},
			}}
		r := &outSwap{
			Request:   req,
			Response:  response,
			Digest:    digest,
			Account:   account,
			ChannelID: channel,
			Expires: s.cfg.Clock.Now().Add(
				time.Duration(req.ExpirySeconds) * time.Second,
			).Unix(),
			Phase:    "registered",
			Circuits: make(map[string]*routerrpc.ForwardHtlcInterceptRequest),
		}

		// Attached value remains reserved until claim or failure
		// determines its ledger outcome; publishing the route does not
		// yet debit the account.
		if attached > 0 {
			a.Reserved += attached
			if err := s.put(
				"credit-account/"+account, a,
			); err != nil {

				return err
			}
			r.CreditID = "receive/" + id
			now := timestamppb.New(s.cfg.Clock.Now())
			credit := &creditRecord{Account: account, Operation: &swaprpc.CreditOperation{OperationId: r.CreditID, Type: swaprpc.CreditOperationType_CREDIT_OPERATION_TYPE_RECEIVE,
				State: swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_RESERVED, AmountSat: attached, PaymentHash: req.PaymentHash, CreatedAt: now, UpdatedAt: now}}
			if err := s.put(
				"credit-operation/"+r.CreditID, credit,
			); err != nil {

				return err
			}
			response.SettlementType = swaprpc.SettlementType_SETTLEMENT_TYPE_MIXED
		}
		if err := s.put("out-swap/"+id, r); err != nil {
			return err
		}
		return s.put(fmt.Sprintf("virtual-channel/%d", channel), id)
	})
	return response, err
}

// emitSwap sends the explicit event wrapper to the receive-specific mailbox.
func (s *Server) emitSwap(r *outSwap, event *swaprpc.SwapMailboxEvent) error {
	// Use the payment-scoped mailbox so concurrent receives owned by one
	// wallet reach the correct client actor.
	pub, err := btcec.ParsePubKey(r.Request.ClientVhtlcPubkey)
	if err != nil {
		return err
	}
	mailbox := serverconn.CompoundMailboxID(
		serverconn.PubKeyMailboxID(pub),
		hex.EncodeToString(r.Request.PaymentHash),
	)
	if err := s.emit(
		mailbox, "swaprpc.SwapService", "SwapMailboxEvent", event,
	); err != nil {

		return err
	}
	s.pending[len(s.pending)-1].envelope.Type = "swap.mailbox_event"
	return nil
}

// circuitID identifies LND's incoming HTLC independently of its payment hash.
func circuitID(key *routerrpc.CircuitKey) string {
	return fmt.Sprintf("%d/%d", key.GetChanId(), key.GetHtlcId())
}

// acceptIntercept records an exact held shard before announcing complete
// receive terms. Unrelated forwarding and final LND invoices resume normally.
// A nil successful response means keep holding the shard. A non-nil response
// is safe to send only after this call succeeds; on error the connection must
// reconnect so LND can replay its durable hold.
func (s *Server) acceptIntercept(ctx context.Context, req *routerrpc.ForwardHtlcInterceptRequest) (*routerrpc.ForwardHtlcInterceptResponse, error) {
	// Default to normal forwarding for unrelated traffic. Once a virtual
	// SCID is recognized, invalid terms fail rather than falling through to
	// routing.
	response := &routerrpc.ForwardHtlcInterceptResponse{
		IncomingCircuitKey: req.IncomingCircuitKey,
		Action:             routerrpc.ResolveHoldForwardAction_RESUME,
	}
	err := s.transact(ctx, func() error {
		id, err := get[string](s, fmt.Sprintf(
			"virtual-channel/%d", req.OutgoingRequestedChanId,
		))
		if err != nil {
			return err
		}
		if id == nil {
			return nil
		}
		r, err := get[outSwap](s, "out-swap/"+*id)
		if err != nil {
			return err
		}
		response.Action = routerrpc.ResolveHoldForwardAction_FAIL
		response.FailureCode = lnrpc.Failure_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS
		if r == nil || req.IncomingCircuitKey == nil ||
			!bytes.Equal(req.PaymentHash, r.Request.PaymentHash) ||
			len(req.OnionBlob) != 1366 {

			return nil
		}

		// LND replays held circuits after reconnect. Accept only the
		// identical shard and return a saved terminal result instead of
		// counting its value twice.
		cid := circuitID(req.IncomingCircuitKey)
		if old := r.Circuits[cid]; old != nil {
			if !proto.Equal(old, req) {
				return errors.New(
					"replayed HTLC circuit changed",
				)
			}
			if len(
				r.Preimage,
			) > 0 {

				response.Action = routerrpc.ResolveHoldForwardAction_SETTLE
				response.Preimage = r.Preimage
				return nil
			}
			if r.Phase == "failed" {
				return nil
			}
			response = nil
			return nil
		}

		// New shards are admitted only while collecting the original
		// payment, with enough expiry runway and a bounded number of
		// held circuits.
		if r.Phase != "registered" && r.Phase != "collecting" {
			return nil
		}
		if s.cfg.Clock.Now().Unix() >= r.Expires ||
			req.IncomingAmountMsat < req.OutgoingAmountMsat ||
			req.OutgoingAmountMsat == 0 ||
			req.IncomingExpiry <= s.height+receiveRouteDelta ||
			len(r.Circuits) >= maxReceiveParts {

			return nil
		}

		// Funding is based on the exact total across distinct shards.
		// Refuse overpayment here rather than silently changing the
		// negotiated receive amount.
		var sum uint64
		for _, part := range r.Circuits {
			sum += part.OutgoingAmountMsat
		}
		if req.OutgoingAmountMsat > r.Request.AmountSat*1000-sum {
			return nil
		}
		sum += req.OutgoingAmountMsat
		r.Circuits[cid] = req
		r.Phase = "collecting"
		if sum == r.Request.AmountSat*1000 {
			// The shortest shard or auto-fail deadline bounds the
			// entire receive. Place the Ark refund earlier so
			// treasury recovery retains a safety margin.
			deadline := req.IncomingExpiry
			for _, part := range r.Circuits {
				deadline = min(deadline, part.IncomingExpiry)
				if part.AutoFailHeight > 0 {
					deadline = min(deadline, uint32(
						part.AutoFailHeight,
					))
				}
			}
			if deadline <= s.height+receiveSafetyMargin+100 {
				return errors.New(
					"receive claim window too short",
				)
			}

			// Only a complete held payment gets final vHTLC terms.
			// The receiver must inspect its onions and acknowledge
			// those terms before treasury funding.
			sender := s.deriveKey("swap-sender/" + *id)
			receiver, err := btcec.ParsePubKey(
				r.Request.ClientVhtlcPubkey,
			)
			if err != nil {
				return err
			}
			r.Config = &swaprpc.VHTLCConfig{RefundLocktime: deadline - receiveSafetyMargin, UnilateralClaimDelay: s.cfg.ExitDelay,
				UnilateralRefundDelay: 2 * s.cfg.ExitDelay, UnilateralRefundWithoutReceiverDelay: 3 * s.cfg.ExitDelay, SwapserverPubkey: sender.PubKey().SerializeCompressed()}
			policy, err := s.swapPolicy(
				sender.PubKey(), receiver,
				r.Request.PaymentHash, r.Config,
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
				"known-policy/"+hex.EncodeToString(r.Script),
				r.Policy,
			); err != nil {

				return err
			}
			event := &swaprpc.OutSwapHtlcEvent{PaymentHash: r.Request.PaymentHash, AmountSat: r.Response.VhtlcAmountSat, VhtlcConfig: r.Config,
				RequestedAmountSat: r.Request.AmountSat, AttachedCreditSat: r.Response.AttachedCreditSat}

			// Present shards in deterministic circuit order so
			// replayed terms retain the same onion and amount
			// sequence.
			ids := make([]string, 0, len(r.Circuits))
			for id := range r.Circuits {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			for _, id := range ids {
				part := r.Circuits[id]
				event.Parts = append(
					event.Parts, &swaprpc.OutSwapHtlcPart{
						AmountMsat: part.OutgoingAmountMsat,
						OnionBlob:  part.OnionBlob,
					},
				)
			}
			event.OnionBlob = event.Parts[0].OnionBlob
			if err := s.emitSwap(r, &swaprpc.SwapMailboxEvent{
				Event: &swaprpc.SwapMailboxEvent_OutSwapHtlc{
					OutSwapHtlc: event,
				},
			}); err != nil {

				return err
			}
			r.Phase = "awaiting-ack"
		}
		response = nil
		return s.put("out-swap/"+*id, r)
	})
	return response, err
}

// AcknowledgeOutSwapHtlc accepts only the receiver's signature over the exact
// persisted policy and amount, before any treasury funding is signed. Success
// records consent but does not guarantee funding. The worker also requires live
// held circuits and enough remaining time before issuing the vHTLC.
func (s *Server) AcknowledgeOutSwapHtlc(ctx context.Context, req *swaprpc.AcknowledgeOutSwapHtlcRequest) (*swaprpc.AcknowledgeOutSwapHtlcResponse, error) {
	// Bind consent to the saved receiver, payment hash, combined amount,
	// and script; a generic acknowledgement must not authorize different
	// funding terms.
	err := s.transact(ctx, func() error {
		if len(
			req.PaymentHash,
		) != 32 {

			return status.Error(
				codes.InvalidArgument, "payment hash required",
			)
		}
		id := hex.EncodeToString(req.PaymentHash)
		r, err := get[outSwap](s, "out-swap/"+id)
		if err != nil {
			return err
		}
		if r == nil || len(
			r.Script,
		) == 0 {

			return status.Error(
				codes.NotFound,
				"receive not awaiting acknowledgement",
			)
		}
		if !bytes.Equal(
			req.ClientVhtlcPubkey, r.Request.ClientVhtlcPubkey,
		) {

			return status.Error(
				codes.PermissionDenied, "receiver key mismatch",
			)
		}
		pub, err := btcec.ParsePubKey(req.ClientVhtlcPubkey)
		if err != nil {
			return err
		}
		digest := swaprpc.OutSwapHTLCAckDigest(
			pub, lntypes.Hash(req.PaymentHash),
			r.Response.VhtlcAmountSat, r.Script,
		)
		sig, err := schnorr.ParseSignature(req.AcknowledgementSignature)
		if err != nil || !sig.Verify(
			digest[:], pub,
		) {

			return status.Error(
				codes.PermissionDenied,
				"invalid receive acknowledgement",
			)
		}

		// A valid late signature cannot revive an expired receive.
		// Exact acknowledgements after funding remain harmless retries.
		if r.Phase == "failed" {
			return status.Error(
				codes.FailedPrecondition, "receive expired",
			)
		}
		r.Ack = req.AcknowledgementSignature
		if r.Phase == "awaiting-ack" {
			r.Phase = "acknowledged"
		}
		return s.put("out-swap/"+id, r)
	})
	if err != nil {
		return nil, err
	}
	return &swaprpc.AcknowledgeOutSwapHtlcResponse{}, nil
}

// observedPreimage extracts a matching preimage from a script-verified OOR
// spend or a Bitcoin-validated on-chain spend of the exact HTLC outpoint.
// The caller must hold s.mu. No matching verified disclosure returns nil, nil;
// malformed saved recovery data returns an error rather than a guessed outcome.
func (s *Server) observedPreimage(outpoint string, hash []byte) ([]byte,
	error) {

	// Prefer a durable chain disclosure, which remains usable even after
	// a reorg removes the transaction that first revealed it.
	disclosed, err := get[chainClaim](s, "chain-claim/"+outpoint)
	if err != nil {
		return nil, err
	}
	if disclosed != nil && len(disclosed.Preimage) == 32 {
		digest := sha256.Sum256(disclosed.Preimage)
		if bytes.Equal(digest[:], hash) {
			return disclosed.Preimage, nil
		}
	}

	// Off-chain disclosure counts only when this indexed output was spent
	// by a finalized session; a submitted but incomplete checkpoint is
	// insufficient.
	coin, err := get[vtxoRecord](s, "vtxo/"+outpoint)
	if err != nil || coin == nil {
		return nil, err
	}
	if coin.VTXO.Status != arkrpc.VTXOStatus_VTXO_STATUS_SPENT ||
		len(coin.VTXO.SpentByTxid) != 32 {

		return nil, nil
	}
	id := chainhash.Hash(coin.VTXO.SpentByTxid)
	r, err := get[oorRecord](s, oorKey(id))
	if err != nil {
		return nil, err
	}
	if r == nil || len(r.Final) == 0 {
		return nil, nil
	}

	// Inspect the exact funding input and execute its completed witness
	// before accepting any 32-byte item as the settlement preimage.
	for _, raw := range r.Final[0].CheckpointPsbts {
		packet, err := psbtutil.Parse(raw)
		if err != nil {
			return nil, err
		}
		if len(
			packet.UnsignedTx.TxIn,
		) != 1 || packet.UnsignedTx.TxIn[0].PreviousOutPoint.String() != outpoint {

			continue
		}
		tx, err := signedPacket(packet)
		if err != nil {
			return nil, err
		}
		for _, item := range tx.TxIn[0].Witness {
			if len(item) != 32 {
				continue
			}
			candidate := sha256.Sum256(item)
			if bytes.Equal(candidate[:], hash) {
				return item, nil
			}
		}
	}
	return nil, nil
}

// reconcileReceives funds acknowledged live circuits and releases their real
// Lightning preimage only after the client's checkpoint is fully finalized.
// active is the connection-owned set of replayed circuit IDs; internal
// receives do not require LND circuits. Callers must discard responses on error
// and send them only after successful persistence.
func (s *Server) reconcileReceives(ctx context.Context,
	active map[string]bool) ([]*routerrpc.ForwardHtlcInterceptResponse,
	error) {

	// Accumulate stream responses inside the state transaction, but send
	// them only after it commits; LND settlement must not outrun durable
	// claim state.
	var responses []*routerrpc.ForwardHtlcInterceptResponse
	err := s.transact(ctx, func() error {
		for key := range s.state.Records {
			if !strings.HasPrefix(key, "out-swap/") {
				continue
			}
			r, err := get[outSwap](s, key)
			if err != nil {
				return err
			}

			// After reconnect, only replayed circuits are known to
			// remain held. Require all shards before risking
			// treasury funding for an external receive.
			allActive := r.Internal || len(r.Circuits) > 0
			for id := range r.Circuits {
				allActive = allActive && active[id]
			}

			// Before funding, expiry can safely cancel the offer
			// and release its credits. Funded outputs instead need
			// claim or refund reconciliation.
			if r.Phase == "registered" || r.Phase == "collecting" ||
				r.Phase == "awaiting-ack" ||
				r.Phase == "acknowledged" {

				expired := s.cfg.Clock.Now().Unix() >= r.Expires
				for _, part := range r.Circuits {
					expired = expired || part.IncomingExpiry <= s.height+receiveSafetyMargin
				}
				if expired {
					r.Phase = "failed"
				}
			}

			// Receiver consent and sufficient remaining claim time
			// gate the real treasury OOR transfer; signing terms
			// alone does not issue a balance.
			if r.Phase == "acknowledged" && allActive {
				if r.Config.RefundLocktime <= s.height+100 {
					r.Phase = "failed"
				} else {
					funding, err := s.fundInventoryOutput(
						ctx, r.Policy,
						r.Response.VhtlcAmountSat,
					)
					if err != nil {
						return err
					}
					r.Session = funding.Session
					r.Outpoint = funding.Outpoint.String()
					r.Phase = "funded"
				}
			}

			// Settle only after verified off-chain or on-chain
			// disclosure proves that the receiver has exercised the
			// funded hashlock.
			if r.Phase == "funded" {
				r.Preimage, err = s.observedPreimage(
					r.Outpoint, r.Request.PaymentHash,
				)
				if err != nil {
					return err
				}
				if len(r.Preimage) > 0 {
					r.Phase = "completed"
					if r.CreditID != "" {
						credit, err := get[creditRecord](s, "credit-operation/"+r.CreditID)
						if err != nil {
							return err
						}
						if err := s.postCredit(
							credit, "debit",
							credit.Operation.AmountSat,
						); err != nil {

							return err
						}
						credit.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_DEBITED
						credit.Operation.CompletedAt = timestamppb.New(s.cfg.Clock.Now())
						if err := s.put(
							"credit-operation/"+r.CreditID,
							credit,
						); err != nil {

							return err
						}
					}
				}
			}

			// Without a claim, recover treasury-owned funding after
			// the agreed absolute refund height. A direct same-Ark
			// sender owns its own refund instead.
			if r.Phase == "funded" && r.Config != nil &&
				r.Config.RefundLocktime <= s.height &&
				len(r.Preimage) == 0 &&
				(!r.Internal || r.Session != "") {

				id := hex.EncodeToString(r.Request.PaymentHash)
				sender := s.deriveKey("swap-sender/" + id)
				receiver, err := btcec.ParsePubKey(
					r.Request.ClientVhtlcPubkey,
				)
				if err != nil {
					return err
				}
				policy, err := s.swapPolicy(
					sender.PubKey(), receiver,
					r.Request.PaymentHash, r.Config,
				)
				if err != nil {
					return err
				}
				path, err := policy.RefundWithoutReceiverPath()
				if err != nil {
					return err
				}
				coin, err := get[vtxoRecord](
					s, "vtxo/"+r.Outpoint,
				)
				if err != nil {
					return err
				}
				if coin == nil {
					return errors.New(
						"receive refund input missing",
					)
				}
				if _, err := s.spendOwnedVTXO(
					ctx, coin, sender, path,
				); err != nil {

					return err
				}
				r.Phase = "failed"
			}
			if r.Phase == "failed" {
				if err := s.releaseCreditReservation(
					r.CreditID, "receive failed",
				); err != nil {

					return err
				}
			}

			// Resolve only circuits replayed on this connection.
			// Saved terminal state handles any remaining shards
			// when LND presents them again.
			if r.Phase == "completed" || r.Phase == "failed" {
				for id, part := range r.Circuits {
					if !active[id] {
						continue
					}
					response := &routerrpc.ForwardHtlcInterceptResponse{
						IncomingCircuitKey: part.IncomingCircuitKey,
						Action:             routerrpc.ResolveHoldForwardAction_FAIL,
						FailureCode:        lnrpc.Failure_INCORRECT_OR_UNKNOWN_PAYMENT_DETAILS,
					}
					if len(
						r.Preimage,
					) > 0 {

						response.Action = routerrpc.ResolveHoldForwardAction_SETTLE
						response.Preimage = r.Preimage
					}
					responses = append(responses, response)
				}
			}
			if err := s.put(key, r); err != nil {
				return err
			}
		}
		return nil
	})
	return responses, err
}

// runInterceptor reconnects LND's durable hold stream until shutdown. Each
// connection owns a receiver goroutine and waits for it before reconnecting.
func (s *Server) runInterceptor() {
	defer s.wg.Done()

	// A failed stream loses readiness immediately; reconnect after a
	// bounded pause while preserving held-circuit decisions in durable
	// state.
	for {
		if s.ctx.Err() != nil {
			return
		}
		err := s.interceptConnection(s.ctx)
		s.mu.Lock()
		s.interceptorReady = false
		s.mu.Unlock()
		if s.ctx.Err() != nil {
			return
		}
		s.cfg.Log.Debug(
			"Lightning interceptor reconnecting", "error", err,
		)
		select {
		case <-s.ctx.Done():
			return

		case <-s.cfg.Clock.TickAfter(time.Second):
		}
	}
}

// interceptConnection serializes stream sends and reconciles held circuit
// state while a separately canceled receiver waits for new LND requests.
func (s *Server) interceptConnection(ctx context.Context) error {
	// Give the receiver a connection-scoped cancellation path so reconnect
	// never leaves an old goroutine blocked on a defunct stream.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream, err := s.cfg.LND.Router.HtlcInterceptor(ctx)
	if err != nil {
		return err
	}

	// One goroutine receives while this function owns all sends. Buffered
	// error delivery lets the receiver exit even during reconciliation.
	requests := make(chan *routerrpc.ForwardHtlcInterceptRequest)
	errorsCh := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			req, err := stream.Recv()
			if err != nil {
				errorsCh <- err
				return
			}
			select {
			case requests <- req:

			case <-ctx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); <-done }()
	s.mu.Lock()
	s.interceptorReady = true
	s.mu.Unlock()

	// Track only circuits actually presented on this stream; durable
	// records alone do not prove that LND is still holding them after
	// reconnect.
	active := make(map[string]bool)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case err := <-errorsCh:
			return err

		case req := <-requests:
			// Persist new holds before adding them to the active
			// set. Immediate resume/fail/replayed-settle responses
			// need no pending funding work.
			response, err := s.acceptIntercept(ctx, req)
			if err != nil {
				return err
			}
			if response != nil {
				if err := stream.Send(response); err != nil {
					return err
				}
			} else {
				active[circuitID(req.IncomingCircuitKey)] = true
			}

		case <-s.cfg.Clock.TickAfter(workerInterval):
			// Commit funding and settlement decisions before
			// sending resolutions. A send failure is recovered by
			// LND replaying the same held circuit.
			responses, err := s.reconcileReceives(ctx, active)
			if err != nil {
				s.cfg.Log.Debug(
					"receive funding pending", "error", err,
				)
				continue
			}
			for _, response := range responses {
				if err := stream.Send(response); err != nil {
					return err
				}
				delete(active, circuitID(
					response.IncomingCircuitKey,
				))
			}
		}
	}
}
