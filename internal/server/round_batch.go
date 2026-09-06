package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	btcaddr "github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/google/uuid"
	"github.com/lightninglabs/wavelength/lib/tree"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AcceptQuote builds and reserves an actual commitment only after acceptance.
func (s *Server) AcceptQuote(ctx context.Context,
	req *roundpb.JoinRoundAccept) (*roundpb.ClientSuccessResp, error) {

	r, err := s.ownedRound(ctx, req.GetRoundId())
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(req.QuoteId, r.Quote.QuoteId) || r.Phase == "dead" {
		return nil, status.Error(
			codes.FailedPrecondition, "quote is not active",
		)
	}
	if r.Batch != nil {
		return r.ack(), s.emitRound(r, roundpb.MethodBatchInfo, r.Batch)
	}
	if s.cfg.Clock.Now().Unix() >= r.Quote.QuoteExpiresAt {
		return nil, status.Error(
			codes.FailedPrecondition, "quote expired",
		)
	}
	if err := s.buildBatch(ctx, r); err != nil {
		return nil, roundError("build", err)
	}
	r.Phase = "nonces"
	if err := s.put(roundKey(r.ID), r); err != nil {
		return nil, err
	}
	return r.ack(), s.emitRound(r, roundpb.MethodBatchInfo, r.Batch)
}

// buildBatch binds tree roots to funded commitment outputs and persists every
// nonce before the client can begin the nonce exchange.
func (s *Server) buildBatch(ctx context.Context, r *roundRecord) error {
	key := s.deriveKey(r.ID + "/tree")
	sweep := s.deriveKey(r.ID + "/sweep")
	commitment := wire.NewMsgTx(2)
	var inputValue int64
	for _, coin := range r.Coins {
		commitment.AddTxIn(wire.NewTxIn(&coin.Outpoint, nil, nil))
		inputValue += coin.Output.Value
	}
	var descriptors []tree.VTXODescriptor
	var outputValue int64
	for i, quote := range r.Quote.VtxoQuotes {
		peer, err := btcec.ParsePubKey(quote.RecipientKey)
		if err != nil {
			return err
		}
		descriptors = append(descriptors, tree.VTXODescriptor{
			PkScript: quote.PkScript, Amount: btcutil.Amount(
				quote.AmountSat,
			),
			CoSignerKey: peer, PolicyTemplate: r.Request.VtxoRequests[i].PolicyTemplate,
		})
	}
	var spec *tree.BatchOutputSpec
	if len(descriptors) > 0 {
		var err error
		spec, err = tree.BuildBatchOutputSpec(
			descriptors, key.PubKey(), sweep.PubKey(),
			s.cfg.BatchLifetime,
		)
		if err != nil {
			return err
		}
		commitment.AddTxOut(spec.Output)
		outputValue += spec.Output.Value
	}
	for _, quote := range r.Quote.LeaveQuotes {
		commitment.AddTxOut(wire.NewTxOut(
			quote.AmountSat, quote.PkScript,
		))
		outputValue += quote.AmountSat
	}
	connectorIndex := len(commitment.TxOut)
	if len(r.Forfeits) > 0 {
		connectorScript, err := txscript.PayToTaprootScript(
			txscript.ComputeTaprootKeyNoScript(s.key.PubKey()),
		)
		if err != nil {
			return err
		}
		value := int64(len(r.Forfeits)) * connectorAmount
		commitment.AddTxOut(wire.NewTxOut(value, connectorScript))
		outputValue += value
	}

	// A conservative regtest subsidy covers even large script-path inputs.
	// It comes from real treasury coins; it never changes quoted amounts.
	fee := int64(1000 * (len(r.Coins) + len(commitment.TxOut) + 2))
	coins, err := s.cfg.LND.Coins(ctx)
	if err != nil {
		return err
	}
	sort.Slice(coins, func(i, j int) bool {
		return coins[i].Outpoint.String() < coins[j].Outpoint.String()
	})
	for _, coin := range coins {
		if inputValue >= outputValue+fee+s.cfg.MinAmount {
			break
		}
		if _, reserved := s.state.Records["reserved/"+coin.Outpoint.String()]; reserved {
			continue
		}
		commitment.AddTxIn(wire.NewTxIn(&coin.Outpoint, nil, nil))
		r.Coins = append(r.Coins, coin)
		inputValue += coin.Output.Value
		fee += 1000
	}
	if inputValue < outputValue+fee+s.cfg.MinAmount {
		return status.Error(
			codes.ResourceExhausted,
			"insufficient confirmed treasury funds",
		)
	}
	address, err := s.cfg.LND.Lightning.NewAddress(
		ctx, &lnrpc.NewAddressRequest{
			Type: lnrpc.AddressType_TAPROOT_PUBKEY,
		},
	)
	if err != nil {
		return err
	}
	decoded, err := btcaddr.DecodeAddress(
		address.Address, &chaincfg.RegressionNetParams,
	)
	if err != nil {
		return err
	}
	script, err := txscript.PayToAddrScript(decoded)
	if err != nil {
		return err
	}
	commitment.AddTxOut(wire.NewTxOut(inputValue-outputValue-fee, script))
	packet, err := psbt.NewFromUnsignedTx(commitment)
	if err != nil {
		return err
	}
	for i, coin := range r.Coins {
		packet.Inputs[i].WitnessUtxo = coin.Output
		if i < len(r.Request.BoardingRequests) {
			path, _, err := standardPath(
				r.Request.BoardingRequests[i].PolicyTemplate,
			)
			if err != nil {
				return err
			}
			if err := path.AttachTapLeafScript(
				&packet.Inputs[i],
			); err != nil {

				return err
			}
		}
	}
	if spec != nil {
		packet.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
			spec.InternalKey,
		)
		packet.Outputs[0].TaprootTapTree = spec.TapTreeBytes()
	}
	var encoded bytes.Buffer
	if err := packet.Serialize(&encoded); err != nil {
		return err
	}
	id, _ := uuid.Parse(r.ID)
	r.Batch = &roundpb.ClientBatchInfo{
		RoundId: id[:], BatchPsbt: encoded.Bytes(),
		VtxoTreePaths: make(map[int32]*roundpb.VTXOTree),
		TreeCosignKey: key.PubKey().SerializeCompressed(),
		SweepKey:      sweep.PubKey().SerializeCompressed(), SweepDelay: s.cfg.BatchLifetime,
		ConnectorOperatorKey: s.key.PubKey().SerializeCompressed(),
		ForfeitKey: s.deriveKey(
			r.ID + "/forfeit",
		).PubKey().SerializeCompressed(),
	}
	if spec != nil {
		t, err := tree.BuildVTXOTree(
			wire.OutPoint{
				Hash:  commitment.TxHash(),
				Index: 0,
			}, spec.Output, descriptors, key.PubKey(),
			sweep.PubKey(), s.cfg.BatchLifetime, 2,
		)
		if err != nil {
			return err
		}
		encodedTree, err := roundpb.TreeToProto(t)
		if err != nil {
			return err
		}
		r.Batch.VtxoTreePaths[0] = encodedTree
		fetcher, err := t.Root.PrevOutputFetcher(t.BatchOutput)
		if err != nil {
			return err
		}
		for node := range t.Root.NodesIter() {
			digest, err := node.SigHash(fetcher)
			if err != nil {
				return err
			}
			txid, err := node.TXID()
			if err != nil {
				return err
			}
			r.Signing[roundpb.TxIDToHex(
				txid,
			)], err = newNodeSigning(key, digest)
			if err != nil {
				return err
			}
		}
	}
	if len(r.Forfeits) > 0 {
		if err := s.buildConnectors(r, commitment, uint32(
			connectorIndex,
		)); err != nil {

			return err
		}
	}
	for _, coin := range r.Coins {
		if err := s.put(
			"reserved/"+coin.Outpoint.String(), r.ID,
		); err != nil {

			return err
		}
	}
	return nil
}

// walkRoundTree visits the persisted tree with authoritative prevout context.
func walkRoundTree(r *roundRecord,
	visit func(*tree.Tree, *tree.Node, string, []byte) error) error {

	for _, encoded := range r.Batch.VtxoTreePaths {
		t, err := roundpb.TreeFromProto(encoded)
		if err != nil {
			return err
		}
		fetcher, err := t.Root.PrevOutputFetcher(t.BatchOutput)
		if err != nil {
			return err
		}
		for node := range t.Root.NodesIter() {
			txid, err := node.TXID()
			if err != nil {
				return err
			}
			digest, err := node.SigHash(fetcher)
			if err != nil {
				return err
			}
			if err := visit(
				t, node, roundpb.TxIDToHex(txid), digest,
			); err != nil {

				return err
			}
		}
	}
	return nil
}

// SubmitNonces aggregates exactly the signers required by each tree node.
func (s *Server) SubmitNonces(ctx context.Context,
	req *roundpb.SubmitNoncesRequest) (*roundpb.ClientVTXOAggNonces,
	error) {

	id, err := roundID(req.GetRoundId())
	if err != nil {
		return nil, err
	}
	r, err := s.ownedRound(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.Batch == nil || r.Phase == "dead" {
		return nil, status.Error(
			codes.FailedPrecondition, "round has no batch",
		)
	}
	key := s.deriveKey(r.ID + "/tree")
	resp := &roundpb.ClientVTXOAggNonces{
		RoundId:   req.RoundId,
		AggNonces: make(map[string][]byte),
	}
	consumed := 0
	err = walkRoundTree(
		r,
		func(t *tree.Tree, node *tree.Node, id string,
			digest []byte) error {

			peers := make(map[string][]byte)
			for _, peer := range node.CoSigners {
				if peer.IsEqual(key.PubKey()) {
					continue
				}
				peerID := hex.EncodeToString(
					peer.SerializeCompressed(),
				)
				peers[peerID] = req.Nonces[peerID].GetTxNonces()[id]
				consumed++
			}
			signing := r.Signing[id]
			if signing == nil {
				return errors.New("missing nonce transcript")
			}
			if err := signing.bindNonces(
				key, node, digest, t.SweepTapscriptRoot, peers,
			); err != nil {

				return err
			}
			resp.AggNonces[id] = signing.Aggregate
			return nil
		},
	)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	supplied := 0
	for _, signer := range req.Nonces {
		supplied += len(signer.GetTxNonces())
	}
	if supplied != consumed {
		return nil, status.Error(
			codes.InvalidArgument, "unexpected nonce entries",
		)
	}
	r.Nonces = resp
	if r.Phase == "nonces" {
		r.Phase = "signatures"
	}
	if err := s.put(roundKey(r.ID), r); err != nil {
		return nil, err
	}
	return resp, s.emitRound(r, roundpb.MethodAggNonces, resp)
}

// SubmitPartialSigs verifies client partials before releasing fully signed
// trees.
func (s *Server) SubmitPartialSigs(ctx context.Context,
	req *roundpb.SubmitPartialSigRequest) (*roundpb.ClientVTXOAggSigs,
	error) {

	id, err := roundID(req.GetRoundId())
	if err != nil {
		return nil, err
	}
	r, err := s.ownedRound(ctx, id)
	if err != nil {
		return nil, err
	}
	if r.Nonces == nil {
		return nil, status.Error(
			codes.FailedPrecondition, "round needs nonces",
		)
	}
	key := s.deriveKey(r.ID + "/tree")
	resp := &roundpb.ClientVTXOAggSigs{
		RoundId: req.RoundId,
		AggSigs: make(map[string][]byte),
	}
	consumed := 0
	err = walkRoundTree(
		r,
		func(t *tree.Tree, node *tree.Node, id string,
			digest []byte) error {

			peers := make(map[string][]byte)
			for _, peer := range node.CoSigners {
				if peer.IsEqual(key.PubKey()) {
					continue
				}
				peerID := hex.EncodeToString(
					peer.SerializeCompressed(),
				)
				peers[peerID] = req.Signatures[peerID].GetTxSigs()[id]
				consumed++
			}
			sig, err := r.Signing[id].combine(
				key.PubKey(), node, digest,
				t.SweepTapscriptRoot, peers,
			)
			if err != nil {
				return err
			}
			resp.AggSigs[id] = sig.Serialize()
			return nil
		},
	)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	supplied := 0
	for _, signer := range req.Signatures {
		supplied += len(signer.GetTxSigs())
	}
	if supplied != consumed {
		return nil, status.Error(
			codes.InvalidArgument, "unexpected signature entries",
		)
	}
	r.Sigs = resp
	if r.Phase == "signatures" {
		r.Phase = "boarding-signatures"
	}
	if err := s.put(roundKey(r.ID), r); err != nil {
		return nil, err
	}
	return resp, s.emitRound(r, roundpb.MethodAggSigs, resp)
}

// SubmitForfeitSigs finalizes boarding inputs only after tree signing
// completes. The transaction is persisted here and broadcast by a separate
// worker.
func (s *Server) SubmitForfeitSigs(ctx context.Context, req *roundpb.SubmitForfeitSigRequest) (*roundpb.ClientAwaitingInputSigsResp, error) {
	id, err := roundID(req.GetRoundId())
	if err != nil {
		return nil, err
	}
	r, err := s.ownedRound(ctx, id)
	if err != nil {
		return nil, err
	}
	resp := &roundpb.ClientAwaitingInputSigsResp{RoundId: req.RoundId}
	if len(r.FinalTx) > 0 {
		return resp, nil
	}
	if r.Batch == nil ||
		(len(r.Request.VtxoRequests) > 0 && r.Sigs == nil) ||
		len(r.SignedForfeits) != len(r.Forfeits) {

		return nil, status.Error(
			codes.FailedPrecondition, "tree signatures required",
		)
	}
	if len(req.Signatures) != len(r.Request.BoardingRequests) {
		return nil, status.Error(
			codes.InvalidArgument, "missing boarding signatures",
		)
	}
	packet, err := psbt.NewFromRawBytes(
		bytes.NewReader(r.Batch.BatchPsbt), false,
	)
	if err != nil {
		return nil, err
	}
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for _, coin := range r.Coins {
		fetcher.AddPrevOut(coin.Outpoint, coin.Output)
	}
	hashes := txscript.NewTxSigHashes(packet.UnsignedTx, fetcher)
	seen := make(map[int]bool)
	for _, submitted := range req.Signatures {
		if submitted == nil {
			return nil, status.Error(
				codes.InvalidArgument, "nil boarding signature",
			)
		}
		i := int(submitted.InputIndex)
		if i < 0 || i >= len(r.Request.BoardingRequests) || seen[i] {
			return nil, status.Error(
				codes.InvalidArgument,
				"invalid boarding input index",
			)
		}
		seen[i] = true
		op, err := roundpb.OutpointFromProto(submitted.Outpoint)
		if err != nil || op != r.Coins[i].Outpoint {
			return nil, status.Error(
				codes.InvalidArgument,
				"boarding outpoint mismatch",
			)
		}
		path, params, err := standardPath(
			r.Request.BoardingRequests[i].PolicyTemplate,
		)
		if err != nil {
			return nil, err
		}
		leaf := txscript.NewBaseTapLeaf(path.WitnessScript)
		digest, err := txscript.CalcTapscriptSignaturehash(
			hashes, txscript.SigHashDefault, packet.UnsignedTx, i,
			fetcher, leaf,
		)
		if err != nil {
			return nil, err
		}
		sig, err := schnorr.ParseSignature(submitted.ClientSignature)
		if err != nil || !sig.Verify(
			digest, params.OwnerKey,
		) {

			return nil, status.Error(
				codes.InvalidArgument,
				"invalid boarding signature",
			)
		}
		own, err := schnorr.Sign(s.key, digest)
		if err != nil {
			return nil, err
		}
		witness, err := path.Witness(own.Serialize(), sig.Serialize())
		if err != nil {
			return nil, err
		}
		var encoded bytes.Buffer
		if err := psbt.WriteTxWitness(&encoded, witness); err != nil {
			return nil, err
		}
		packet.Inputs[i].FinalScriptWitness = encoded.Bytes()
	}
	var encoded bytes.Buffer
	if err := packet.Serialize(&encoded); err != nil {
		return nil, err
	}
	final, err := s.cfg.LND.Wallet.FinalizePsbt(
		ctx, &walletrpc.FinalizePsbtRequest{
			FundedPsbt: encoded.Bytes(),
		},
	)
	if err != nil {
		return nil, roundError("finalize wallet inputs", err)
	}
	var signed wire.MsgTx
	if err := signed.Deserialize(bytes.NewReader(
		final.RawFinalTx,
	)); err != nil {

		return nil, err
	}
	if signed.TxHash() != packet.UnsignedTx.TxHash() {
		return nil, errors.New("wallet changed commitment")
	}
	if err := verifyTransaction(&signed, fetcher); err != nil {
		return nil, err
	}
	r.FinalTx, r.Phase = final.RawFinalTx, "ready-to-broadcast"
	return resp, s.put(roundKey(r.ID), r)
}

// pollRounds publishes only committed signed transactions and records their
// confirmations. Publication retries use identical bytes across restarts.
func (s *Server) pollRounds(ctx context.Context) error {
	s.mu.Lock()
	var rounds []*roundRecord
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "round/") {
			continue
		}
		r, err := get[roundRecord](s, key)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if len(r.FinalTx) > 0 {
			rounds = append(rounds, r)
		}
	}
	s.mu.Unlock()
	for _, r := range rounds {
		var tx wire.MsgTx
		if err := tx.Deserialize(bytes.NewReader(
			r.FinalTx,
		)); err != nil {

			return err
		}
		confs, blockHash, err := s.cfg.Bitcoin.Transaction(
			ctx, tx.TxHash().String(),
		)
		if err != nil || confs <= 0 {
			if err := s.cfg.Bitcoin.Publish(
				ctx, r.FinalTx,
			); err != nil {

				return fmt.Errorf("publish round %s: %w", r.ID, err)
			}
		}
		var confirmedHeight uint32
		if confs > 0 {
			confirmedHeight, err = s.cfg.Bitcoin.BlockHeight(
				ctx, blockHash,
			)
			if err != nil {
				return err
			}
		}
		newStatus := roundpb.RoundLifecycleStatus_ROUND_STATUS_BROADCAST
		if confs > 0 {
			newStatus = roundpb.RoundLifecycleStatus_ROUND_STATUS_CONFIRMED
		}
		if r.Status == newStatus {
			continue
		}
		if err := s.transact(ctx, func() error {
			current, err := get[roundRecord](s, roundKey(r.ID))
			if err != nil {
				return err
			}
			current.Status = newStatus
			if confs > 0 {
				current.Phase = "confirmed"
				current.ConfirmedHeight = confirmedHeight
				if err := s.indexRound(current); err != nil {
					return err
				}
			} else {
				current.Phase = "broadcast"
			}
			return s.put(roundKey(r.ID), current)
		}); err != nil {

			return err
		}
	}
	return nil
}
