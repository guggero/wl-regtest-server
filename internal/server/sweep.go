package server

import (
	"bytes"
	"context"
	"errors"
	"strings"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/lib/tree"
	"github.com/lightninglabs/wavelength/lib/tx/psbtutil"
	"github.com/lightningnetwork/lnd/lnrpc"
)

const (
	// expirySweepFee pays a conservative fixed mining fee for one root
	// input.
	expirySweepFee int64 = 1000
)

// sweepExpiredRoots recovers still-unspent batch roots only after Bitcoin's
// actual CSV maturity. The operator's original timeout leaf is used unchanged;
// users retain the complete exit window advertised in their commitment.
func (s *Server) sweepExpiredRoots(ctx context.Context) error {
	// Snapshot confirmed rounds whose recorded age makes recovery
	// plausible; Bitcoin will be queried separately for their current
	// maturity.
	s.mu.Lock()
	var rounds []*roundRecord
	height := s.height
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "round/") {
			continue
		}
		round, err := get[roundRecord](s, key)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if round.ConfirmedHeight > 0 && round.Batch != nil && len(
			round.Batch.VtxoTreePaths,
		) > 0 && uint64(
			height,
		) >= uint64(
			round.ConfirmedHeight,
		)+uint64(
			round.Batch.SweepDelay,
		) {

			rounds = append(rounds, round)
		}
	}
	s.mu.Unlock()

	// A reorg or a user exit can invalidate the snapshot. Require the
	// actual root to remain unspent and CSV-mature before preparing a
	// sweep.
	for _, round := range rounds {
		packet, err := psbtutil.Parse(round.Batch.BatchPsbt)
		if err != nil {
			return err
		}
		root := wire.OutPoint{
			Hash:  packet.UnsignedTx.TxHash(),
			Index: 0,
		}
		coin, err := s.cfg.Bitcoin.UTXO(ctx, root)
		if errors.Is(err, backend.ErrOutputSpent) {
			continue
		}
		if err != nil {
			return err
		}
		if coin.Confirmations < int64(round.Batch.SweepDelay) ||
			coin.Output.Value <= expirySweepFee+s.cfg.MinAmount {

			continue
		}

		// Reuse the durable transaction after retries or restart,
		// rather than creating competing sweeps with fresh wallet
		// destinations.
		key := "expiry-sweep/" + round.ID
		s.mu.Lock()
		persisted, err := get[[]byte](s, key)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if persisted == nil {
			// Recovered funds return to the connected LND wallet so
			// later rounds can reuse them; obtain its destination
			// only for a new sweep.
			rpcCtx, cancel := context.WithTimeout(
				ctx, backend.RPCTimeout,
			)
			destination, err := s.cfg.LND.Lightning.NewAddress(
				rpcCtx, &lnrpc.NewAddressRequest{
					Type: lnrpc.AddressType_TAPROOT_PUBKEY,
				},
			)
			cancel()
			if err != nil {
				return err
			}
			decoded, err := address.DecodeAddress(
				destination.Address,
				&chaincfg.RegressionNetParams,
			)
			if err != nil {
				return err
			}
			script, err := txscript.PayToAddrScript(decoded)
			if err != nil {
				return err
			}
			raw, err := s.buildExpirySweep(
				round, packet, coin, script,
			)
			if err != nil {
				return err
			}

			// Save the exact signed bytes before broadcast so a
			// crash cannot lose the identity of an already
			// published recovery transaction.
			if err := s.transact(ctx, func() error {
				return s.put(key, raw)
			}); err != nil {

				return err
			}
			persisted = &raw
		}
		if err := s.cfg.Bitcoin.Publish(ctx, *persisted); err != nil {
			return err
		}
		s.cfg.Log.Debug(
			"published expired root sweep", "round", round.ID,
			"root", root.String(),
		)
	}
	return nil
}

// buildExpirySweep signs and independently executes the original branch timeout
// script before retaining any broadcastable recovery transaction. batch must
// contain the original root metadata at output zero; coin must be the
// authoritative root UTXO and destination a wallet output script. The caller
// checks CSV maturity and value before requesting the fixed-fee sweep.
func (s *Server) buildExpirySweep(round *roundRecord, batch *psbt.Packet,
	coin *backend.Coin, destination []byte) ([]byte, error) {

	// Reconstruct the original timeout leaf from the persisted batch terms.
	// Current configuration must not shorten the users' committed exit
	// window.
	internal, err := schnorr.ParsePubKey(
		batch.Outputs[0].TaprootInternalKey,
	)
	if err != nil {
		return nil, err
	}
	key := s.deriveKey(round.ID + "/sweep")
	spend, err := tree.NewBranchSweepSpendInfo(
		internal, key.PubKey(), round.Batch.SweepDelay,
	)
	if err != nil {
		return nil, err
	}

	// Version two and the original block sequence activate CSV. The fixed
	// fee is deducted from this root alone, without adding wallet inputs.
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&coin.Outpoint, nil, nil))
	tx.TxIn[0].Sequence = round.Batch.SweepDelay
	tx.AddTxOut(wire.NewTxOut(
		coin.Output.Value-expirySweepFee, destination,
	))

	// Branch roots use their MuSig2 aggregate internal key. The VTXO
	// signing helper deliberately requires NUMS and is unsuitable here.
	fetcher := txscript.NewCannedPrevOutputFetcher(
		coin.Output.PkScript, coin.Output.Value,
	)
	hashes := txscript.NewTxSigHashes(tx, fetcher)
	signature, err := txscript.RawTxInTapscriptSignature(
		tx, hashes, 0, coin.Output.Value, coin.Output.PkScript,
		txscript.NewBaseTapLeaf(spend.WitnessScript),
		txscript.SigHashDefault, key,
	)
	if err != nil {
		return nil, err
	}
	tx.TxIn[0].Witness = wire.TxWitness{
		signature, spend.WitnessScript, spend.ControlBlock,
	}

	// Validate the assembled recovery witness before saving broadcastable
	// bytes; a wrong key, control block, or sequence must fail locally.
	if err := verifyTransaction(tx, fetcher); err != nil {
		return nil, err
	}
	var raw bytes.Buffer
	if err := tx.Serialize(&raw); err != nil {
		return nil, err
	}
	return raw.Bytes(), nil
}
