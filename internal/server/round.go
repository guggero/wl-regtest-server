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
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/google/uuid"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/bip322"
	"github.com/lightninglabs/wavelength/lib/types"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/lightningnetwork/lnd/keychain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

const (
	// quoteLifetime allows slow integration clients to evaluate their
	// quote.
	quoteLifetime = 5 * time.Minute

	// maxRoundItems caps validation and tree work for a single participant.
	maxRoundItems = 64
)

// roundRecord describes one participant's round. The small operator seals each
// intent separately, retaining all client-visible protocol phases. A quote
// reserves user inputs; acceptance fixes the funded batch and nonce sessions.
// Tree signatures precede input signatures, and FinalTx is saved before
// broadcast. Status is the public lifecycle; Phase tracks the finer internal
// signing steps.
type roundRecord struct {
	ID              string
	Owner           string
	Request         *roundpb.JoinRoundRequest
	Quote           *roundpb.JoinRoundQuote
	Coins           []backend.Coin
	Forfeits        []*vtxoRecord
	ConnectorTree   *roundpb.VTXOTree
	SignedForfeits  map[string][]byte
	Batch           *roundpb.ClientBatchInfo
	Signing         map[string]*nodeSigning
	Nonces          *roundpb.ClientVTXOAggNonces
	Sigs            *roundpb.ClientVTXOAggSigs
	FinalTx         []byte
	Status          roundpb.RoundLifecycleStatus
	Phase           string
	Created         int64
	ConfirmedHeight uint32
}

// roundKey identifies a persisted round independently of its mailbox delivery.
func roundKey(id string) string { return "round/" + id }

// roundID validates a binary UUID before using it to address persisted state.
func roundID(raw []byte) (string, error) {
	id, err := uuid.FromBytes(raw)
	if err != nil || id == uuid.Nil {
		return "", status.Error(
			codes.InvalidArgument, "invalid round ID",
		)
	}
	return id.String(), nil
}

// ownedRound authorizes operations by the mailbox that admitted the intent.
// The caller must hold s.mu; missing and foreign-owned rounds both return
// NotFound, avoiding disclosure through a guessed round ID.
func (s *Server) ownedRound(ctx context.Context, id string) (*roundRecord,
	error) {

	if _, err := uuid.Parse(id); err != nil {
		return nil, status.Error(
			codes.InvalidArgument, "invalid round ID",
		)
	}

	// Hide other participants' rounds behind the same response as missing
	// rounds; knowing a UUID does not grant authority over its funds.
	r, err := get[roundRecord](s, roundKey(id))
	if err != nil {
		return nil, err
	}
	if r == nil || r.Owner != principal(ctx) {
		return nil, status.Error(codes.NotFound, "round not found")
	}
	return r, nil
}

// ack reconstructs the admission event used to correlate the client actor.
func (r *roundRecord) ack() *roundpb.ClientSuccessResp {
	// Use the admitted request rather than current coin status so replay
	// correlates the same inputs even after the round has completed.
	id, _ := uuid.Parse(r.ID)
	ack := &roundpb.ClientSuccessResp{RoundId: id[:]}
	for _, req := range r.Request.BoardingRequests {
		ack.AcceptedBoardingOutpoints = append(
			ack.AcceptedBoardingOutpoints, req.Outpoint,
		)
	}
	for _, req := range r.Request.ForfeitRequests {
		ack.AcceptedVtxoOutpoints = append(
			ack.AcceptedVtxoOutpoints, req.VtxoOutpoint,
		)
	}
	return ack
}

// joinDomain decodes only public intent fields for canonical BIP-322 binding.
func joinDomain(req *roundpb.JoinRoundRequest) (*types.JoinRoundRequest,
	error) {

	key, err := btcec.ParsePubKey(req.Identifier)
	if err != nil {
		return nil, err
	}

	// Preserve request ordering and public intent fields when rebuilding
	// the message covered by the client's proof of ownership.
	domain := &types.JoinRoundRequest{Identifier: key}
	for _, in := range req.BoardingRequests {
		if in == nil {
			return nil, errors.New("nil boarding input")
		}
		op, err := roundpb.OutpointFromProto(in.Outpoint)
		if err != nil {
			return nil, err
		}
		domain.BoardingReqs = append(
			domain.BoardingReqs, &types.BoardingRequest{
				Outpoint: &op, PolicyTemplate: in.PolicyTemplate,
			},
		)
	}
	for _, out := range req.VtxoRequests {
		if out == nil || out.TargetAmountSat < 0 {
			return nil, errors.New("invalid VTXO request")
		}
		key, err := btcec.ParsePubKey(out.SigningKey)
		if err != nil {
			return nil, err
		}
		domain.VTXOReqs = append(domain.VTXOReqs, &types.VTXORequest{
			Amount: btcutil.Amount(
				out.TargetAmountSat,
			), IsChange: out.IsChange,
			FixedAmount: out.FixedAmount, PolicyTemplate: out.PolicyTemplate,
			SigningKey: keychain.KeyDescriptor{PubKey: key},
		})
	}

	// Custom policies carry their authorization and forfeit branches in the
	// intent, preventing substitution after the owner signs the request.
	for _, in := range req.ForfeitRequests {
		if in == nil {
			return nil, errors.New("nil forfeit input")
		}
		op, err := roundpb.OutpointFromProto(in.VtxoOutpoint)
		if err != nil {
			return nil, err
		}
		f := &types.ForfeitRequest{VTXOOutpoint: &op}
		if len(in.AuthSpendPath) > 0 {
			f.AuthSpend, err = arkscript.DecodeSpendPath(
				in.AuthSpendPath,
			)
			if err != nil {
				return nil, err
			}
		}
		if len(in.ForfeitSpendPath) > 0 {
			f.ForfeitSpend, err = arkscript.DecodeSpendPath(
				in.ForfeitSpendPath,
			)
			if err != nil {
				return nil, err
			}
		}
		domain.ForfeitReqs = append(domain.ForfeitReqs, f)
	}

	// On-chain destinations are part of the same authorization as VTXOs;
	// bind both the script and the requested amount before checking proofs.
	for _, out := range req.LeaveRequests {
		if out == nil || out.TargetAmountSat < 0 ||
			len(out.PkScript) == 0 {

			return nil, errors.New("invalid leave request")
		}
		domain.LeaveReqs = append(domain.LeaveReqs, &types.LeaveRequest{
			Output: wire.NewTxOut(
				out.TargetAmountSat, out.PkScript,
			), IsChange: out.IsChange,
		})
	}
	return domain, nil
}

// JoinRound verifies actual funds and their BIP-322 proof before reserving
// them. It runs inside the authenticated mailbox transaction, which atomically
// saves reservations, the quote, and response events. Amounts are satoshis and
// proof validity is evaluated at the server's observed block height.
func (s *Server) JoinRound(ctx context.Context,
	req *roundpb.JoinRoundRequest) (*roundpb.ClientSuccessResp, error) {

	// Admission needs an authenticated return mailbox and a bounded intent
	// before any backend work or signature validation is attempted.
	if req == nil || req.Auth == nil || principal(ctx) == "" {
		return nil, status.Error(
			codes.InvalidArgument, "authenticated intent required",
		)
	}
	nIn := len(req.BoardingRequests) + len(req.ForfeitRequests)
	nOut := len(req.VtxoRequests) + len(req.LeaveRequests)
	if nIn == 0 || nIn > maxRoundItems || nOut == 0 ||
		nOut > maxRoundItems {

		return nil, status.Error(
			codes.InvalidArgument, "invalid round item count",
		)
	}

	// Reconstruct the canonical authorization from the request itself so a
	// valid proof cannot be paired with different destinations or inputs.
	domain, err := joinDomain(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	message, err := types.JoinRoundAuthMessage(domain)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if !bytes.Equal(message, req.Auth.Message) {
		return nil, status.Error(
			codes.InvalidArgument,
			"intent does not match authorization",
		)
	}

	// A semantic retry cannot create another round or reserve its funds
	// twice.
	digest := sha256.Sum256(append([]byte(principal(ctx)), message...))
	intentKey := "intent/" + hex.EncodeToString(digest[:])
	old, err := get[string](s, intentKey)
	if err != nil {
		return nil, err
	}
	if old != nil {
		r, err := s.ownedRound(ctx, *old)
		if err != nil {
			return nil, err
		}
		if r.Phase != "dead" {
			return r.ack(), s.emitRound(
				r, roundpb.MethodJoinAck, r.ack(),
			)
		}
	}
	if req.RoundId != "" {
		return nil, status.Error(
			codes.InvalidArgument, "new intents must omit round ID",
		)
	}

	// A fresh intent accumulates authoritative prevouts before reserving
	// anything; the surrounding transaction rolls back all rejected
	// admissions.
	r := &roundRecord{ID: uuid.NewString(), Owner: principal(ctx),
		Request: proto.Clone(req).(*roundpb.JoinRoundRequest),
		Status:  roundpb.RoundLifecycleStatus_ROUND_STATUS_IN_FLIGHT,
		Phase:   "quoted", Created: s.cfg.Clock.Now().Unix(),
		Signing: make(map[string]*nodeSigning)}
	prev := make(map[wire.OutPoint]*wire.TxOut)
	var total int64
	for _, in := range domain.BoardingReqs {
		if _, exists := prev[*in.Outpoint]; exists {
			return nil, status.Error(
				codes.InvalidArgument, "duplicate input",
			)
		}
		lock, err := get[string](s, "reserved/"+in.Outpoint.String())
		if err != nil {
			return nil, err
		}
		if lock != nil {
			return nil, status.Error(
				codes.FailedPrecondition,
				"boarding input reserved",
			)
		}
		coin, err := s.cfg.Bitcoin.UTXO(ctx, *in.Outpoint)
		if err != nil {
			return nil, err
		}
		if coin == nil || coin.Confirmations < 1 ||
			coin.Output.Value < s.cfg.MinAmount {

			return nil, status.Error(
				codes.FailedPrecondition,
				"boarding input not confirmed or below minimum",
			)
		}

		// The boarding output must commit to this operator and leave
		// enough time for the advertised refund path; client-supplied
		// policy bytes alone are not evidence of what was funded.
		path, params, err := standardPath(in.PolicyTemplate)
		if err != nil {
			return nil, status.Error(
				codes.InvalidArgument, err.Error(),
			)
		}
		if !bytes.Equal(schnorr.SerializePubKey(params.OperatorKey), schnorr.SerializePubKey(s.key.PubKey())) ||
			params.ExitDelay < s.cfg.BoardingDelay {

			return nil, status.Error(
				codes.InvalidArgument,
				"invalid boarding policy",
			)
		}
		if err := path.VerifyBindsToPkScript(
			coin.Output.PkScript,
		); err != nil {

			return nil, status.Error(
				codes.InvalidArgument, err.Error(),
			)
		}
		prev[*in.Outpoint] = coin.Output
		r.Coins = append(r.Coins, *coin)
		total += coin.Output.Value
	}

	// Off-chain inputs must still be live and exclusively available. Their
	// confirmed ancestry replaces the direct UTXO check used for boarding.
	for _, in := range domain.ForfeitReqs {
		outpoint := *in.VTXOOutpoint
		if prev[outpoint] != nil {
			return nil, status.Error(
				codes.InvalidArgument, "duplicate round input",
			)
		}
		if _, reserved := s.state.Records["reserved/"+outpoint.String()]; reserved {
			return nil, status.Error(
				codes.FailedPrecondition, "VTXO reserved",
			)
		}
		record, err := get[vtxoRecord](s, "vtxo/"+outpoint.String())
		if err != nil {
			return nil, err
		}
		if record == nil || record.VTXO.Status != arkrpc.VTXOStatus_VTXO_STATUS_LIVE || record.VTXO.BatchExpiryHeight <= int32(
			s.height+s.cfg.ExitDelay,
		) {

			return nil, status.Error(
				codes.FailedPrecondition, "VTXO not spendable",
			)
		}
		if err := s.checkVTXORoots(ctx, record); err != nil {
			return nil, status.Error(
				codes.FailedPrecondition, err.Error(),
			)
		}

		// Custom policies must identify a bound collaborative branch;
		// standard VTXOs can use the conventional owner/operator branch
		// implicitly.
		path := in.ForfeitSpend
		if path == nil {
			path, _, err = standardPath(record.Policy)
			if err != nil {
				return nil, status.Error(
					codes.InvalidArgument,
					"custom forfeit path required",
				)
			}
		}
		if err := path.VerifyBindsToPkScript(
			record.VTXO.PkScript,
		); err != nil {

			return nil, status.Error(
				codes.InvalidArgument, err.Error(),
			)
		}

		// The operator must participate in the forfeiture, and each
		// input value must fit the monetary range before contributing
		// to the quote.
		policy, err := arkscript.DecodePolicyTemplate(record.Policy)
		if err != nil {
			return nil, err
		}
		keys, err := arkscript.SigningKeysForSpendPath(policy, path)
		if err != nil || !hasKey(keys, s.key.PubKey()) {
			return nil, status.Error(
				codes.InvalidArgument,
				"forfeit path needs operator",
			)
		}
		value := int64(record.VTXO.ValueSat)
		if value <= 0 || value > btcutil.MaxSatoshi-total {
			return nil, status.Error(
				codes.InvalidArgument, "round value overflow",
			)
		}
		total += value
		prev[outpoint] = wire.NewTxOut(value, record.VTXO.PkScript)
		r.Forfeits = append(r.Forfeits, record)
	}

	// Verify ownership against authoritative amounts and scripts, not the
	// metadata supplied alongside the client's proof.
	challenge, err := bip322.JoinRoundMessageChallenge(domain.Identifier)
	if err != nil {
		return nil, err
	}
	auth, err := bip322.NewIntentAuthContext(
		message, req.Auth.ValidFrom, req.Auth.ValidUntil, challenge,
		req.Auth.Signature, prev, &s.height,
	)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if len(auth.Sig.ToSign.TxIn) != len(prev)+1 {
		return nil, status.Error(
			codes.InvalidArgument, "proof must cover every input",
		)
	}

	// The proof must cover the exact input set once each; a valid signature
	// for only a subset cannot authorize reserving the remaining funds.
	seen := make(map[wire.OutPoint]bool)
	for _, in := range auth.Sig.ToSign.TxIn[1:] {
		if prev[in.PreviousOutPoint] == nil ||
			seen[in.PreviousOutPoint] {

			return nil, status.Error(
				codes.InvalidArgument, "unexpected proof input",
			)
		}
		seen[in.PreviousOutPoint] = true
	}
	if result := auth.Validate(); result.State != bip322.VerificationStateValid {
		return nil, status.Error(
			codes.PermissionDenied,
			"invalid input proof: "+result.Reason,
		)
	}

	// Only a fully authorized, balanced intent can reserve funds. Save its
	// semantic retry key alongside the round and both admission events.
	r.Quote, err = s.quote(r, total)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	for op := range prev {
		if err := s.put("reserved/"+op.String(), r.ID); err != nil {
			return nil, err
		}
	}
	if err := s.put(intentKey, r.ID); err != nil {
		return nil, err
	}
	if err := s.put(roundKey(r.ID), r); err != nil {
		return nil, err
	}
	if err := s.emitRound(r, roundpb.MethodJoinAck, r.ack()); err != nil {
		return nil, err
	}
	return r.ack(), s.emitRound(r, roundpb.MethodJoinRoundQuote, r.Quote)
}

// quote computes residual amounts once, applying the client's fixed/change
// semantics. Regtest treasury funding subsidizes the commitment mining fee.
// total is the admitted input value in satoshis. The request must already be
// structurally decoded; the returned quote is not persisted by this helper.
func (s *Server) quote(r *roundRecord, total int64) (*roundpb.JoinRoundQuote,
	error) {

	// One immutable quote per round lets acceptance and retries refer to
	// the same amounts and expiry without renegotiating the intent.
	qID := sha256.Sum256([]byte(r.ID + "/quote/0"))
	q := &roundpb.JoinRoundQuote{RoundId: r.ID, QuoteId: qID[:],
		QuoteExpiresAt: s.cfg.Clock.Now().Add(quoteLifetime).Unix()}
	count := len(r.Request.VtxoRequests) + len(r.Request.LeaveRequests)
	change, fixed := 0, int64(0)

	// Validate exit policies while deriving their scripts; a destination
	// that the client can compile must also satisfy the advertised exit
	// terms.
	for _, req := range r.Request.VtxoRequests {
		policy, err := arkscript.DecodePolicyTemplate(
			req.PolicyTemplate,
		)
		if err != nil {
			return nil, err
		}
		nodes := make([]arkscript.Node, len(policy.Leaves))
		for i, leaf := range policy.Leaves {
			nodes[i] = leaf.Node
		}
		if err := arkscript.ValidatePolicy(
			nodes, arkscript.PolicyValidationOpts{
				OperatorKey:  s.key.PubKey(),
				MinExitDelay: s.cfg.ExitDelay,
			},
		); err != nil {

			return nil, err
		}
		script, err := policy.PkScript()
		if err != nil {
			return nil, err
		}

		// A sole flexible VTXO absorbs the residual implicitly. Mark
		// its value unresolved until every fixed destination has been
		// accounted for.
		isChange := req.IsChange || count == 1 && !req.FixedAmount
		if req.IsChange && req.FixedAmount {
			return nil, errors.New("fixed output cannot be change")
		}
		value := req.TargetAmountSat
		if isChange {
			change++
			value = -1
		} else {
			if value > btcutil.MaxSatoshi-fixed {
				return nil, errors.New("output amount overflow")
			}
			fixed += value
		}
		q.VtxoQuotes = append(q.VtxoQuotes, &roundpb.VTXOQuote{
			PkScript:     script,
			AmountSat:    value,
			RecipientKey: req.SigningKey,
		})
	}

	// Leave outputs share the same residual pool as VTXOs, so there can be
	// only one change destination across both kinds of output.
	for _, req := range r.Request.LeaveRequests {
		value := req.TargetAmountSat
		if req.IsChange || count == 1 {
			change++
			value = -1
		} else {
			if value > btcutil.MaxSatoshi-fixed {
				return nil, errors.New("output amount overflow")
			}
			fixed += value
		}
		q.LeaveQuotes = append(q.LeaveQuotes, &roundpb.LeaveQuote{
			PkScript:  req.PkScript,
			AmountSat: value,
		})
	}

	// Require exact conservation before resolving change. Treasury subsidy
	// covers fees separately and must not mask an unbalanced user intent.
	if change > 1 || change == 0 && fixed != total || fixed > total {
		return nil, errors.New(
			"intent must balance with at most one change output",
		)
	}
	for _, out := range q.VtxoQuotes {
		if out.AmountSat == -1 {
			out.AmountSat = total - fixed
		}
		if out.AmountSat < s.cfg.MinAmount {
			return nil, errors.New("VTXO below minimum")
		}
	}

	// Apply the same minimum after resolving on-chain change, and reject
	// scripts that cannot serve as a spendable collaborative exit.
	for _, out := range q.LeaveQuotes {
		if out.AmountSat == -1 {
			out.AmountSat = total - fixed
		}
		if out.AmountSat < s.cfg.MinAmount ||
			txscript.IsUnspendable(out.PkScript) {

			return nil, errors.New("invalid leave output")
		}
	}
	return q, nil
}

// emitRound schedules a typed protocol event for the round's participant. The
// caller must be inside a state transaction; delivery is staged until commit.
func (s *Server) emitRound(r *roundRecord, method string,
	msg proto.Message) error {

	return s.emit(r.Owner, roundpb.ServiceName, method, msg)
}

// RejectQuote releases a round only while no signing artifacts exist.
// This mailbox handler requires the dispatcher transaction. A wrong owner or
// quote is rejected, and an accepted batch cannot be canceled through this RPC.
func (s *Server) RejectQuote(ctx context.Context,
	req *roundpb.JoinRoundReject) (*roundpb.ClientSuccessResp, error) {

	// Releasing reservations is safe only before tree construction exposes
	// signing artifacts that could still consume the admitted funds.
	r, err := s.ownedRound(ctx, req.GetRoundId())
	if err != nil {
		return nil, err
	}
	if r.Phase != "quoted" || !bytes.Equal(req.QuoteId, r.Quote.QuoteId) {
		return nil, status.Error(
			codes.FailedPrecondition, "quote cannot be rejected",
		)
	}

	// Mark the admission dead and release both direct and virtual inputs in
	// the enclosing mailbox transaction so no partially released round
	// survives.
	r.Phase, r.Status = "dead", roundpb.RoundLifecycleStatus_ROUND_STATUS_DEAD
	for _, coin := range r.Coins {
		delete(s.state.Records, "reserved/"+coin.Outpoint.String())
	}
	for _, input := range r.Request.ForfeitRequests {
		op, err := roundpb.OutpointFromProto(input.VtxoOutpoint)
		if err != nil {
			return nil, err
		}
		delete(s.state.Records, "reserved/"+op.String())
	}
	return r.ack(), s.put(roundKey(r.ID), r)
}

// QueryRoundStatus returns a durable status event for client recovery. This
// mailbox handler requires the dispatcher transaction. Unknown or foreign-owned
// IDs receive a dead status without exposing another owner's round.
func (s *Server) QueryRoundStatus(ctx context.Context,
	req *roundpb.QueryRoundStatusRequest) (*roundpb.ClientSuccessResp,
	error) {

	id, err := roundID(req.GetRoundId())
	if err != nil {
		return nil, err
	}
	r, err := get[roundRecord](s, roundKey(id))
	if err != nil {
		return nil, err
	}

	// Report an unknown round as dead without revealing another mailbox
	// owner's state; the requesting actor can then terminate recovery.
	if r == nil || r.Owner != principal(ctx) {
		r = &roundRecord{
			ID: id,
			Owner: principal(
				ctx,
			),
			Request: &roundpb.JoinRoundRequest{},
			Status:  roundpb.RoundLifecycleStatus_ROUND_STATUS_DEAD,
			Phase:   "unknown",
		}
	}
	return r.ack(), s.emitRound(
		r, roundpb.MethodRoundStatusReport,
		&roundpb.ClientRoundStatusReport{
			RoundId: req.RoundId,
			Status:  r.Status,
			Detail:  r.Phase,
		},
	)
}

// roundError attaches the phase that failed without hiding the original error.
func roundError(phase string, err error) error {
	return fmt.Errorf("round %s: %w", phase, err)
}

// expireQuotes releases only unsigned admissions; once a signing artifact has
// escaped, its input reservations remain tied to the durable round forever.
func (s *Server) expireQuotes(ctx context.Context) error {
	// Use the same rejection path as an explicit client cancellation, but
	// only for unsigned quotes whose advertised lifetime has elapsed.
	return s.transact(ctx, func() error {
		for key := range s.state.Records {
			if !strings.HasPrefix(key, "round/") {
				continue
			}
			r, err := get[roundRecord](s, key)
			if err != nil {
				return err
			}
			if r.Phase != "quoted" || r.Batch != nil || r.Quote == nil || r.Quote.QuoteExpiresAt > s.cfg.Clock.Now().Unix() {
				continue
			}
			_, err = s.RejectQuote(
				context.WithValue(ctx, principalKey{}, r.Owner),
				&roundpb.JoinRoundReject{
					RoundId: r.ID,
					QuoteId: r.Quote.QuoteId,
				},
			)
			if err != nil {
				return err
			}
		}
		return nil
	})
}
