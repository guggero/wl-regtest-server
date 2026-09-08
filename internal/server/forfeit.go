package server

import (
	"bytes"
	"context"
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/tree"
	arktx "github.com/lightninglabs/wavelength/lib/tx"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// connectorAmount funds each connector leaf with a standard dust
	// output.
	connectorAmount = int64(330)
)

// buildConnectors constructs and signs the deterministic operator-only tree
// clients reconstruct to bind each forfeit to this exact commitment. commitment
// must already contain the connector funding output at index. The caller saves
// the mutated round and batch within its enclosing transaction.
func (s *Server) buildConnectors(r *roundRecord, commitment *wire.MsgTx,
	index uint32) error {

	// Anchor every connector in this commitment so the associated penalties
	// become usable only if the replacement batch is published.
	output := commitment.TxOut[index]
	t, err := tree.BuildConnectorTree(
		wire.OutPoint{
			Hash:  commitment.TxHash(),
			Index: index,
		}, output, tree.ConnectorDescriptor{PkScript: output.PkScript,
			NumLeaves: len(r.Forfeits), Amount: 330}, s.key.PubKey(), 2,
	)
	if err != nil {
		return err
	}

	// Connector branches are operator-only key-path spends. Apply their
	// BIP86 tweak and verify the whole tree before assigning leaves to
	// inputs.
	fetcher, err := t.Root.PrevOutputFetcher(output)
	if err != nil {
		return err
	}
	key := txscript.TweakTaprootPrivKey(*s.key, nil)
	for node := range t.Root.NodesIter() {
		digest, err := node.SigHash(fetcher)
		if err != nil {
			return err
		}
		sig, err := schnorr.Sign(key, digest)
		if err != nil {
			return err
		}
		node.AddSignature(sig)
	}
	if err := t.VerifySigned(); err != nil {
		return err
	}
	r.ConnectorTree, err = roundpb.TreeToProto(t)
	if err != nil {
		return err
	}

	// Preserve admitted input order when assigning leaves so clients can
	// reconstruct exactly which connector binds each forfeit.
	r.Batch.ConnectorLeafMap = make(map[string]*roundpb.ConnectorLeafInfo)
	for i, leaf := range t.Root.GetLeafNodes() {
		outpoint, err := leaf.GetNonAnchorOutpoint()
		if err != nil {
			return err
		}
		input, err := roundpb.OutpointFromProto(
			r.Request.ForfeitRequests[i].VtxoOutpoint,
		)
		if err != nil {
			return err
		}
		r.Batch.ConnectorLeafMap[input.String()] = &roundpb.ConnectorLeafInfo{
			LeafOutpoint: &roundpb.Outpoint{
				TxHash:      outpoint.Hash[:],
				OutputIndex: outpoint.Index,
			},
			LeafOutput: &roundpb.TxOut{
				Value:    connectorAmount,
				PkScript: output.PkScript,
			},
			RootOutputIndex: index, NumLeaves: uint32(len(
				r.Forfeits,
			)), Radix: 2, LeafIndex: uint32(i),
		}
	}
	return nil
}

// SubmitVTXOForfeitSigs verifies and persists connector-bound penalties before
// permitting the replacement commitment to become broadcastable. It runs inside
// the mailbox transaction and requires a signed replacement tree when the round
// creates VTXOs. Retries must preserve the original penalties.
func (s *Server) SubmitVTXOForfeitSigs(ctx context.Context,
	req *roundpb.SubmitVTXOForfeitSigsRequest) (*roundpb.ClientSuccessResp,
	error) {

	// Do not accept surrender of old VTXOs until the replacement exit tree
	// is signed and the exact connector set has been committed to the
	// round.
	id, err := roundID(req.GetRoundId())
	if err != nil {
		return nil, err
	}
	r, err := s.ownedRound(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.Batch == nil || r.ConnectorTree == nil ||
		(len(r.Request.VtxoRequests) > 0 && r.Sigs == nil) ||
		len(req.ForfeitTxs) != len(r.Forfeits) {

		return nil, status.Error(
			codes.FailedPrecondition,
			"round not ready for forfeits",
		)
	}

	// Require one complete, validated penalty per input; duplicates must
	// not satisfy the expected forfeit count.
	signed := make(map[string][]byte)
	for _, submitted := range req.ForfeitTxs {
		if submitted == nil {
			return nil, status.Error(
				codes.InvalidArgument, "nil forfeit",
			)
		}
		outpoint, err := roundpb.OutpointFromProto(
			submitted.VtxoOutpoint,
		)
		if err != nil {
			return nil, err
		}
		if _, exists := signed[outpoint.String()]; exists {
			return nil, status.Error(
				codes.InvalidArgument, "duplicate forfeit",
			)
		}
		raw, err := s.signForfeit(r, submitted, outpoint)
		if err != nil {
			return nil, status.Error(
				codes.InvalidArgument, err.Error(),
			)
		}
		signed[outpoint.String()] = raw
	}

	// A retry must reproduce the penalties already retained, since changing
	// them after commitment signing could invalidate recovery assumptions.
	if len(r.SignedForfeits) > 0 {
		for key, raw := range signed {
			if !bytes.Equal(r.SignedForfeits[key], raw) {
				return nil, status.Error(
					codes.AlreadyExists,
					"forfeit transcript changed",
				)
			}
		}
	} else {
		r.SignedForfeits = signed
	}
	if err := s.put(roundKey(r.ID), r); err != nil {
		return nil, err
	}

	// A pure refresh or collaborative exit has no boarding signatures left
	// to collect, so completing forfeits can advance commitment
	// finalization.
	if len(r.Request.BoardingRequests) == 0 && len(r.FinalTx) == 0 {
		_, err := s.SubmitForfeitSigs(
			ctx, &roundpb.SubmitForfeitSigRequest{
				RoundId: req.RoundId,
			},
		)
		if err != nil {
			return nil, err
		}
	}
	return r.ack(), nil
}

// signForfeit compares the unsigned penalty transaction to the admitted spend
// path and connector, verifies every participant, and executes both inputs.
// It returns serialized witness transaction bytes without publishing them.
// The round must already contain its admitted inputs and assigned connectors.
func (s *Server) signForfeit(r *roundRecord, submitted *roundpb.ForfeitTxSig,
	outpoint wire.OutPoint) ([]byte, error) {

	// Resolve the admitted input and its assigned connector from durable
	// round state; submitted metadata cannot choose another penalty
	// dependency.
	connector := r.Batch.ConnectorLeafMap[outpoint.String()]
	if connector == nil {
		return nil, errors.New("forfeit input not in round")
	}
	var record *vtxoRecord
	var intent *roundpb.ForfeitRequest
	for i, request := range r.Request.ForfeitRequests {
		input, err := roundpb.OutpointFromProto(request.VtxoOutpoint)
		if err != nil {
			return nil, err
		}
		if input == outpoint {
			record, intent = r.Forfeits[i], request
		}
	}
	if record == nil {
		return nil, errors.New("missing forfeit VTXO")
	}

	// The owner authorized a specific spend branch when joining. Compare
	// that branch before using any submitted participant signatures.
	path, err := arkscript.DecodeSpendPath(submitted.SpendPath)
	if err != nil {
		return nil, err
	}
	var wanted *arkscript.SpendPath
	if len(intent.ForfeitSpendPath) == 0 {
		wanted, _, err = standardPath(record.Policy)
	} else {
		wanted, err = arkscript.DecodeSpendPath(intent.ForfeitSpendPath)
	}
	if err != nil {
		return nil, err
	}

	// The legacy forfeit builder treats zero as the final sequence. Apply
	// that same normalization before comparing the admitted transcript.
	if path.RequiredSequence == 0 {
		path.RequiredSequence = wire.MaxTxInSequenceNum
	}
	if wanted.RequiredSequence == 0 {
		wanted.RequiredSequence = wire.MaxTxInSequenceNum
	}
	wantedBytes, err := wanted.Encode()
	if err != nil {
		return nil, err
	}
	pathBytes, err := path.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(wantedBytes, pathBytes) {
		return nil, errors.New("forfeit path changed")
	}

	// Reconstruct the operator destination and connector independently,
	// then enforce the public forfeit shape, amount, and transaction
	// version.
	connectorOutpoint, err := roundpb.OutpointFromProto(
		connector.LeafOutpoint,
	)
	if err != nil {
		return nil, err
	}
	penalty, err := txscript.PayToTaprootScript(
		txscript.ComputeTaprootKeyNoScript(s.deriveKey(r.ID + "/forfeit").PubKey()),
	)
	if err != nil {
		return nil, err
	}
	var tx wire.MsgTx
	if err := tx.Deserialize(bytes.NewReader(
		submitted.UnsignedTx,
	)); err != nil {

		return nil, err
	}
	if err := arktx.ValidateForfeitTx(&tx, arktx.ForfeitTxParams{
		VTXOOutpoint: outpoint, ConnectorOutpoint: connectorOutpoint, ServerForfeitScript: penalty,
		ExpectedSequence: path.RequiredSequence, ExpectedLockTime: path.RequiredLockTime,
	}); err != nil {

		return nil, err
	}
	if tx.TxOut[0].Value != int64(record.VTXO.ValueSat)+connectorAmount ||
		tx.Version != 3 {

		return nil, errors.New("incorrect forfeit value or version")
	}

	// Use indexed VTXO and connector prevouts for signature hashing; values
	// from the submitted transaction cannot establish the amounts being
	// spent.
	packet, err := psbt.NewFromUnsignedTx(&tx)
	if err != nil {
		return nil, err
	}
	packet.Inputs[0].WitnessUtxo = wire.NewTxOut(
		int64(record.VTXO.ValueSat), record.VTXO.PkScript,
	)
	packet.Inputs[1].WitnessUtxo = wire.NewTxOut(
		connectorAmount, connector.LeafOutput.PkScript,
	)
	policy, err := arkscript.DecodePolicyTemplate(record.Policy)
	if err != nil {
		return nil, err
	}
	keys, err := arkscript.SigningKeysForSpendPath(policy, path)
	if err != nil {
		return nil, err
	}
	leafHash := txscript.NewBaseTapLeaf(path.WitnessScript).TapHash()

	// The legacy single-signature field is unambiguous only for a two-key
	// policy. More complex leaves require explicit participant identities.
	signatures := submitted.ParticipantSigs
	if len(signatures) == 0 {
		if len(
			keys,
		) != 2 {

			return nil, errors.New(
				"participant signatures required",
			)
		}
		for _, key := range keys {
			if !bytes.Equal(
				schnorr.SerializePubKey(key),
				schnorr.SerializePubKey(s.key.PubKey()),
			) {

				signatures = []*roundpb.ForfeitParticipantSig{
					{
						Pubkey:    schnorr.SerializePubKey(key),
						Signature: submitted.ClientVtxoSig,
					},
				}
			}
		}
	}
	for _, sig := range signatures {
		if sig == nil {
			return nil, errors.New("nil participant signature")
		}

		// The wire protocol permits compressed participant keys; PSBT
		// keys are always x-only, including three-party vHTLC refunds.
		var pub *btcec.PublicKey
		if len(sig.Pubkey) == schnorr.PubKeyBytesLen {
			pub, err = schnorr.ParsePubKey(sig.Pubkey)
		} else {
			pub, err = btcec.ParsePubKey(sig.Pubkey)
		}
		if err != nil {
			return nil, err
		}
		packet.Inputs[0].TaprootScriptSpendSig = append(
			packet.Inputs[0].TaprootScriptSpendSig,
			&psbt.TaprootScriptSpendSig{
				XOnlyPubKey: schnorr.SerializePubKey(pub),
				LeafHash:    leafHash[:],
				Signature:   sig.Signature,
			},
		)
	}

	// Complete the VTXO script path and the operator connector key path.
	// Final witness execution below validates all submitted participants
	// together.
	if err := signPacketInput(packet, 0, s.key, path); err != nil {
		return nil, err
	}
	fetcher, err := packetPrevouts(packet)
	if err != nil {
		return nil, err
	}
	hashes := txscript.NewTxSigHashes(&tx, fetcher)
	digest, err := txscript.CalcTaprootSignatureHash(
		hashes, txscript.SigHashDefault, &tx, 1, fetcher,
	)
	if err != nil {
		return nil, err
	}
	key := txscript.TweakTaprootPrivKey(*s.key, nil)
	sig, err := schnorr.Sign(key, digest)
	if err != nil {
		return nil, err
	}
	packet.Inputs[1].TaprootKeySpendSig = sig.Serialize()

	// Retain a penalty only after both inputs execute successfully, rather
	// than trusting a syntactically complete collection of signatures.
	final, err := signedPacket(packet)
	if err != nil {
		return nil, err
	}
	var raw bytes.Buffer
	if err := final.Serialize(&raw); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}
