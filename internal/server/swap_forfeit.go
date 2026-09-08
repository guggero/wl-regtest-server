package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	arktx "github.com/lightninglabs/wavelength/lib/tx"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/lightninglabs/wavelength/swaprpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// participantForfeit retains the exact remotely signed refresh transcript.
type participantForfeit struct {
	Payload   *swaprpc.ForfeitSignaturePayload
	Receiver  []byte
	Signature *swaprpc.ForfeitParticipantSignature
}

// forfeitPacket validates a swap refresh against an admitted round, its real
// connector tree, and an equal-value replacement with the identical policy. The
// caller must hold s.mu. Payload amounts are satoshis; returned metadata uses
// values already checked against indexed funding and the admitted connector.
func (s *Server) forfeitPacket(
	p *swaprpc.ForfeitSignaturePayload) (*psbt.Packet, *arkscript.SpendPath,
	error) {

	// The request ID commits to the complete canonical payload. Verify that
	// binding before using the ID to cache or solicit a participant
	// signature.
	if p == nil || len(p.RequestId) != 32 || len(p.PaymentHash) != 32 ||
		len(p.UnsignedForfeitTx) > 100000 {

		return nil, nil, errors.New("invalid forfeit payload")
	}
	unsigned := proto.Clone(p).(*swaprpc.ForfeitSignaturePayload)
	unsigned.RequestId = nil
	raw, err := marshal(unsigned)
	if err != nil {
		return nil, nil, err
	}
	digest := sha256.Sum256(raw)
	if !bytes.Equal(digest[:], p.RequestId) {
		return nil, nil, errors.New(
			"forfeit request ID does not bind transcript",
		)
	}

	// A remote refresh request must refer to the actual indexed conditional
	// coin; payload amounts and scripts are not authoritative.
	coin, err := get[vtxoRecord](s, "vtxo/"+p.VhtlcOutpoint)
	if err != nil {
		return nil, nil, err
	}
	if coin == nil || coin.VTXO.ValueSat != p.VhtlcAmountSat ||
		!bytes.Equal(coin.Policy, p.VhtlcPolicyTemplate) ||
		!bytes.Equal(coin.VTXO.PkScript, p.VhtlcPkScript) {

		return nil, nil, errors.New(
			"forfeit input differs from funded VTXO",
		)
	}

	// Find the admitted round through its assigned connector. This proves
	// the penalty is conditional on a real replacement commitment.
	var selected *roundRecord
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "round/") {
			continue
		}
		r, err := get[roundRecord](s, key)
		if err != nil {
			return nil, nil, err
		}
		if r.Batch == nil || r.Phase == "dead" {
			continue
		}
		connector := r.Batch.ConnectorLeafMap[p.VhtlcOutpoint]
		if connector == nil {
			continue
		}
		op, err := roundpb.OutpointFromProto(connector.LeafOutpoint)
		if err != nil {
			return nil, nil, err
		}
		if op.String() != p.ConnectorOutpoint {
			continue
		}
		if uint64(
			connector.LeafOutput.Value,
		) != p.ConnectorAmountSat || !bytes.Equal(
			connector.LeafOutput.PkScript, p.ConnectorPkScript,
		) {

			return nil, nil, errors.New(
				"forfeit connector mismatch",
			)
		}
		selected = r
		break
	}
	if selected == nil {
		return nil, nil, errors.New(
			"forfeit has no admitted round connector",
		)
	}

	// Require both the operator's actual penalty destination and an
	// admitted equal-value replacement preserving the swap's original
	// policy.
	penalty, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(
			s.deriveKey(selected.ID + "/forfeit").PubKey(),
		),
	)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(penalty, p.ServerForfeitPkScript) {
		return nil, nil, errors.New("forfeit penalty mismatch")
	}
	admitted := false
	for _, request := range selected.Request.ForfeitRequests {
		op, err := roundpb.OutpointFromProto(request.VtxoOutpoint)
		if err != nil {
			return nil, nil, err
		}
		if op.String() == p.VhtlcOutpoint && bytes.Equal(
			request.ForfeitSpendPath, p.ForfeitSpendPath,
		) {

			admitted = true
		}
	}
	replacement := false
	for i, request := range selected.Request.VtxoRequests {
		if bytes.Equal(
			request.PolicyTemplate, p.VhtlcPolicyTemplate,
		) && uint64(
			selected.Quote.VtxoQuotes[i].AmountSat,
		) == p.VhtlcAmountSat {

			replacement = true
		}
	}
	if !admitted || !replacement {
		return nil, nil, errors.New(
			"swap refresh must preserve its admitted policy and " +
				"value",
		)
	}

	// Only the admitted leaf may authorize this penalty; validate the
	// transaction shape and timelocks before constructing signing metadata.
	path, err := arkscript.DecodeSpendPath(p.ForfeitSpendPath)
	if err != nil {
		return nil, nil, err
	}
	if err := path.VerifyBindsToPkScript(coin.VTXO.PkScript); err != nil {
		return nil, nil, err
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(
		p.UnsignedForfeitTx,
	)); err != nil {

		return nil, nil, err
	}
	if len(tx.TxIn) != 2 ||
		tx.TxIn[0].PreviousOutPoint.String() != p.VhtlcOutpoint ||
		tx.TxIn[1].PreviousOutPoint.String() != p.ConnectorOutpoint {

		return nil, nil, errors.New("forfeit outpoint mismatch")
	}
	if err := arktx.ValidateForfeitTx(&tx, arktx.ForfeitTxParams{
		VTXOOutpoint:        tx.TxIn[0].PreviousOutPoint,
		ConnectorOutpoint:   tx.TxIn[1].PreviousOutPoint,
		ServerForfeitScript: penalty,
		ExpectedSequence:    path.RequiredSequence,
		ExpectedLockTime:    path.RequiredLockTime,
	}); err != nil {

		return nil, nil, err
	}
	if tx.Version != 3 || tx.TxOut[0].Value != int64(
		p.VhtlcAmountSat+p.ConnectorAmountSat,
	) {

		return nil, nil, errors.New("forfeit value or version mismatch")
	}

	// Populate prevouts only after their supplied values and scripts have
	// been checked against the indexed coin and admitted connector.
	packet, err := psbt.NewFromUnsignedTx(&tx)
	if err != nil {
		return nil, nil, err
	}
	packet.Inputs[0].WitnessUtxo = wire.NewTxOut(
		int64(p.VhtlcAmountSat), p.VhtlcPkScript,
	)
	packet.Inputs[1].WitnessUtxo = wire.NewTxOut(
		int64(p.ConnectorAmountSat), p.ConnectorPkScript,
	)
	return packet, path, nil
}

// SignInSwapForfeit signs a connector-bound refresh with the swap participant
// key, or requests the same-Ark receiver's share through its durable mailbox.
// Request identity binds the entire payload. Waiting for a remote participant
// honors ctx; cancellation preserves the durable request for a later retry.
func (s *Server) SignInSwapForfeit(ctx context.Context, req *swaprpc.SignInSwapForfeitRequest) (*swaprpc.SignInSwapForfeitResponse, error) {
	// Validate the refresh and cache its participant transcript before
	// returning a local share or asking a remote receiver to sign.
	var response *swaprpc.SignInSwapForfeitResponse
	var requestID string
	err := s.transact(ctx, func() error {
		p := req.GetPayload()
		packet, path, err := s.forfeitPacket(p)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		id := hex.EncodeToString(p.PaymentHash)
		r, err := get[inSwap](s, "in-swap/"+id)
		if err != nil {
			return err
		}
		if r == nil || !bytes.Equal(r.Policy, p.VhtlcPolicyTemplate) ||
			r.Outpoint != p.VhtlcOutpoint {

			return status.Error(
				codes.FailedPrecondition,
				"forfeit does not match funded in-swap",
			)
		}

		// Retries recover a previously requested or completed share
		// without starting a second remote signing request for the same
		// transcript.
		requestID = hex.EncodeToString(p.RequestId)
		old, err := get[participantForfeit](
			s, "participant-forfeit/"+requestID,
		)
		if err != nil {
			return err
		}
		if old != nil {
			if !proto.Equal(old.Payload, p) {
				return status.Error(
					codes.AlreadyExists,
					"forfeit transcript changed",
				)
			}
			if old.Signature != nil {
				response = &swaprpc.SignInSwapForfeitResponse{
					Signature: old.Signature,
				}
			}
			return nil
		}
		record := &participantForfeit{
			Payload:  p,
			Receiver: r.Response.ServerPubkey,
		}

		// The operator does not own the direct same-Ark receiver key.
		// Ask that receiver through its authenticated mailbox instead
		// of substituting our key.
		if r.InArk {
			local, err := get[outSwap](s, "out-swap/"+id)
			if err != nil {
				return err
			}
			if local == nil {
				return errors.New("same-Ark receiver missing")
			}
			if err := s.emitSwap(local, &swaprpc.SwapMailboxEvent{
				Event: &swaprpc.SwapMailboxEvent_OutSwapForfeitSignatureRequest{
					OutSwapForfeitSignatureRequest: &swaprpc.OutSwapForfeitSignatureRequest{
						Payload: p,
					},
				},
			}); err != nil {

				return err
			}
		} else {

			// For external swaps the treasury owns the receiver
			// key, but it may sign only a branch that actually
			// includes that key in the funded policy.
			key := s.deriveKey("swap-receiver/" + id)
			policy, err := arkscript.DecodePolicyTemplate(r.Policy)
			if err != nil {
				return err
			}
			keys, err := arkscript.SigningKeysForSpendPath(
				policy, path,
			)
			if err != nil || !hasKey(
				keys, key.PubKey(),
			) {

				return status.Error(
					codes.InvalidArgument,
					"forfeit leaf does not include swap "+
						"receiver",
				)
			}
			if err := signPacketInput(
				packet, 0, key, path,
			); err != nil {

				return err
			}
			record.Signature = &swaprpc.ForfeitParticipantSignature{
				Pubkey:    key.PubKey().SerializeCompressed(),
				Signature: packet.Inputs[0].TaprootScriptSpendSig[0].Signature,
			}
			response = &swaprpc.SignInSwapForfeitResponse{
				Signature: record.Signature,
			}
		}
		return s.put("participant-forfeit/"+requestID, record)
	})
	if err != nil {
		return nil, err
	}
	if response != nil {
		return response, nil
	}

	// Wait outside the transaction for the remote share. Cancellation ends
	// this RPC while preserving the request for a later client retry.
	for {
		s.mu.Lock()
		record, err := get[participantForfeit](
			s, "participant-forfeit/"+requestID,
		)
		wake := s.wake
		s.mu.Unlock()
		if err != nil {
			return nil, err
		}
		if record.Signature != nil {
			return &swaprpc.SignInSwapForfeitResponse{
				Signature: record.Signature,
			}, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()

		case <-wake:
		}
	}
}

// SubmitOutSwapForfeitSignature accepts a receiver share only for a transcript
// the operator previously requested, and verifies it against both real inputs.
// An exact repeated share is accepted; a different signature for the saved
// request is rejected. Success persists the share and wakes any waiting payer.
func (s *Server) SubmitOutSwapForfeitSignature(ctx context.Context, req *swaprpc.SubmitOutSwapForfeitSignatureRequest) (*swaprpc.SubmitOutSwapForfeitSignatureResponse, error) {
	// An unsolicited share cannot create a signing session. Match the saved
	// request and expected receiver before rebuilding its signing digest.
	err := s.transact(ctx, func() error {
		p := req.GetPayload()
		if p == nil || len(
			p.RequestId,
		) != 32 || req.Signature == nil {

			return status.Error(
				codes.InvalidArgument,
				"forfeit payload and signature required",
			)
		}
		key := "participant-forfeit/" + hex.EncodeToString(p.RequestId)
		record, err := get[participantForfeit](s, key)
		if err != nil {
			return err
		}
		if record == nil || !proto.Equal(record.Payload, p) ||
			!bytes.Equal(record.Receiver, req.Signature.Pubkey) {

			return status.Error(
				codes.PermissionDenied,
				"unrequested receiver forfeit transcript",
			)
		}
		packet, path, err := s.forfeitPacket(p)
		if err != nil {
			return status.Error(codes.InvalidArgument, err.Error())
		}
		pub, err := btcec.ParsePubKey(req.Signature.Pubkey)
		if err != nil {
			return status.Error(
				codes.InvalidArgument,
				"invalid participant key",
			)
		}

		// The receiver signature commits to both the VTXO and connector
		// prevouts under the admitted script leaf and SIGHASH_DEFAULT.
		prev, err := packetPrevouts(packet)
		if err != nil {
			return err
		}
		hashes := txscript.NewTxSigHashes(packet.UnsignedTx, prev)
		digest, err := txscript.CalcTapscriptSignaturehash(
			hashes, txscript.SigHashDefault, packet.UnsignedTx, 0,
			prev, txscript.NewBaseTapLeaf(path.WitnessScript),
		)
		if err != nil {
			return err
		}
		sig, err := schnorr.ParseSignature(req.Signature.Signature)
		if err != nil || !sig.Verify(
			digest, pub,
		) {

			return status.Error(
				codes.PermissionDenied,
				"invalid receiver forfeit signature",
			)
		}

		// Once accepted, the participant share is immutable; waking the
		// waiting payer must always reveal the same durable signing
		// transcript.
		if record.Signature != nil &&
			!proto.Equal(record.Signature, req.Signature) {

			return status.Error(
				codes.AlreadyExists,
				"receiver signature changed",
			)
		}
		record.Signature = req.Signature
		return s.put(key, record)
	})
	if err != nil {
		return nil, err
	}
	return &swaprpc.SubmitOutSwapForfeitSignatureResponse{}, nil
}

// reconcileRefreshedSwaps moves funding references to equal-value replacement
// vHTLCs once their signed refresh commitment confirms.
// The caller must run inside the round-indexing transaction after replacement
// VTXOs have been recorded; this helper does not change negotiated swap terms.
func (s *Server) reconcileRefreshedSwaps(round *roundRecord) error {
	// A confirmed refresh replaces an old conditional output only with the
	// same policy and value in this round, preserving the negotiated swap
	// rights.
	for _, input := range round.Request.ForfeitRequests {
		op, err := roundpb.OutpointFromProto(input.VtxoOutpoint)
		if err != nil {
			return err
		}
		old, err := get[vtxoRecord](s, "vtxo/"+op.String())
		if err != nil {
			return err
		}
		var replacement string
		for key := range s.state.Records {
			if !strings.HasPrefix(key, "vtxo/") {
				continue
			}
			coin, err := get[vtxoRecord](s, key)
			if err != nil {
				return err
			}
			if coin.VTXO.RoundId == round.ID &&
				coin.VTXO.ValueSat == old.VTXO.ValueSat &&
				bytes.Equal(coin.Policy, old.Policy) {

				replacement = strings.TrimPrefix(key, "vtxo/")
				break
			}
		}
		if replacement == "" {
			continue
		}

		// Move both payer and receiver references together with round
		// indexing so later claims and refunds target the confirmed
		// replacement output.
		for key := range s.state.Records {
			switch {
			case strings.HasPrefix(key, "in-swap/"):
				r, err := get[inSwap](s, key)
				if err != nil {
					return err
				}
				if r.Outpoint == op.String() {
					r.Outpoint = replacement
					if err := s.put(key, r); err != nil {
						return err
					}
				}

			case strings.HasPrefix(key, "out-swap/"):
				r, err := get[outSwap](s, key)
				if err != nil {
					return err
				}
				if r.Outpoint == op.String() {
					r.Outpoint = replacement
					if err := s.put(key, r); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}
