package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"testing"

	"github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/tree"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/stretchr/testify/require"
)

// expirySweepFixture creates an actual public-library branch commitment with
// a short CSV delay. Its timeout key uses the same derivation as real rounds.
func expirySweepFixture(t *testing.T) (*Server, *roundRecord, *psbt.Packet,
	*backend.Coin) {

	t.Helper()
	s := testServer(t, t.TempDir())
	round := &roundRecord{ID: "expiry-test", Batch: &roundpb.ClientBatchInfo{
		SweepDelay: 10,
	}}
	script, err := txscript.PayToTaprootScript(s.key.PubKey())
	require.NoError(t, err)
	spec, err := tree.BuildBatchOutputSpec(
		[]tree.VTXODescriptor{{
			PkScript: script, Amount: 100000, CoSignerKey: s.key.PubKey(),
		}}, s.deriveKey(round.ID+"/tree").PubKey(),
		s.deriveKey(round.ID+"/sweep").PubKey(), round.Batch.SweepDelay,
	)
	require.NoError(t, err)
	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(&wire.OutPoint{}, nil, nil))
	tx.AddTxOut(spec.Output)
	packet, err := psbt.NewFromUnsignedTx(tx)
	require.NoError(t, err)
	packet.Outputs[0].TaprootInternalKey = schnorr.SerializePubKey(
		spec.InternalKey,
	)
	coin := &backend.Coin{
		Outpoint: wire.OutPoint{Hash: tx.TxHash()}, Output: spec.Output,
	}
	return s, round, packet, coin
}

// TestExpirySweepWitness verifies that expiry recovery binds the real branch
// script and CSV delay, and rejects a changed operator timeout key.
func TestExpirySweepWitness(t *testing.T) {
	s, round, packet, coin := expirySweepFixture(t)
	raw, err := s.buildExpirySweep(
		round, packet, coin, coin.Output.PkScript,
	)
	require.NoError(t, err)
	var tx wire.MsgTx
	require.NoError(t, tx.Deserialize(bytes.NewReader(raw)))
	require.Equal(t, round.Batch.SweepDelay, tx.TxIn[0].Sequence)
	require.Equal(t, coin.Output.Value-expirySweepFee, tx.TxOut[0].Value)
	round.ID = "wrong-timeout-key"
	_, err = s.buildExpirySweep(round, packet, coin, coin.Output.PkScript)
	require.Error(t, err)
}

// TestExpirySweepBitcoin checks CSV admission against a real Bitcoin Core
// mempool, then mines the signed timeout spend and verifies its output. It also
// checks admission across a real invalidate/reconsider cycle.
func TestExpirySweepBitcoin(t *testing.T) {
	if os.Getenv("WL_INTEGRATION") != "1" {
		t.Skip("set WL_INTEGRATION=1 with a funded regtest RPC wallet")
	}
	s, round, packet, coin := expirySweepFixture(t)
	bitcoin := &backend.Bitcoin{
		URL: os.Getenv(
			"WL_TEST_BITCOIN_RPC",
		), User: os.Getenv(
			"WL_TEST_BITCOIN_USER",
		),
		Password: os.Getenv("WL_TEST_BITCOIN_PASSWORD"),
	}
	if bitcoin.URL == "" {
		bitcoin.URL = "http://127.0.0.1:18443"
	}
	if bitcoin.User == "" {
		bitcoin.User = "regtest"
	}
	if bitcoin.Password == "" {
		bitcoin.Password = "regtest"
	}
	info, err := bitcoin.Info(t.Context())
	require.NoError(t, err)
	require.Equal(t, "regtest", info.Chain)
	root, err := address.NewAddressTaproot(
		coin.Output.PkScript[2:], &chaincfg.RegressionNetParams,
	)
	require.NoError(t, err)
	var txid, miner string
	require.NoError(t, bitcoin.Call(t.Context(), "sendtoaddress", []any{
		root.EncodeAddress(), float64(coin.Output.Value) / 1e8,
	}, &txid))
	hash, err := chainhash.NewHashFromStr(txid)
	require.NoError(t, err)
	var funded struct {
		Vout []struct {
			N      uint32 `json:"n"`
			Script struct {
				Hex string `json:"hex"`
			} `json:"scriptPubKey"`
		} `json:"vout"`
	}
	require.NoError(t, bitcoin.Call(
		t.Context(), "getrawtransaction", []any{txid, true}, &funded,
	))
	for _, out := range funded.Vout {
		if out.Script.Hex == hex.EncodeToString(coin.Output.PkScript) {
			coin.Outpoint = wire.OutPoint{Hash: *hash, Index: out.N}
		}
	}
	require.Equal(t, *hash, coin.Outpoint.Hash)
	require.NoError(t, bitcoin.Call(
		t.Context(), "getnewaddress", []any{}, &miner,
	))
	require.NoError(t, bitcoin.Call(
		t.Context(), "generatetoaddress", []any{1, miner}, nil,
	))

	// A real shallow reorg removes the backing confirmation. Admission
	// must stop until Bitcoin Core accepts the original block again.
	s.cfg.Bitcoin = bitcoin
	record := &vtxoRecord{VTXO: &arkrpc.VTXO{
		AncestryPaths: []*arkrpc.AncestryPath{{
			TreePath: &arkrpc.TreePath{BatchOutpoint: &arkrpc.OutPoint{
				Txid: coin.Outpoint.Hash[:], Vout: coin.Outpoint.Index,
			}},
		}},
	}}
	require.NoError(t, s.checkVTXORoots(t.Context(), record))
	tip, err := bitcoin.Info(t.Context())
	require.NoError(t, err)
	require.NoError(t, bitcoin.Call(
		t.Context(), "invalidateblock", []any{
			tip.BestBlockHash,
		}, nil,
	))
	t.Cleanup(func() {
		_ = bitcoin.Call(context.Background(), "reconsiderblock", []any{
			tip.BestBlockHash,
		}, nil)
	})
	require.Error(t, s.checkVTXORoots(t.Context(), record))
	require.NoError(t, bitcoin.Call(
		t.Context(), "reconsiderblock", []any{
			tip.BestBlockHash,
		}, nil,
	))
	require.NoError(t, s.checkVTXORoots(t.Context(), record))
	raw, err := s.buildExpirySweep(
		round, packet, coin, coin.Output.PkScript,
	)
	require.NoError(t, err)
	var acceptance []struct {
		Allowed bool   `json:"allowed"`
		Reason  string `json:"reject-reason"`
	}
	check := func() {
		t.Helper()
		require.NoError(t, bitcoin.Call(
			t.Context(), "testmempoolaccept",
			[]any{[]string{hex.EncodeToString(raw)}}, &acceptance,
		))
		require.Len(t, acceptance, 1)
	}
	check()
	require.False(t, acceptance[0].Allowed)
	require.Equal(t, "non-BIP68-final", acceptance[0].Reason)
	require.NoError(t, bitcoin.Call(
		t.Context(), "generatetoaddress",
		[]any{round.Batch.SweepDelay - 1, miner}, nil,
	))
	check()
	require.True(t, acceptance[0].Allowed, acceptance[0].Reason)
	require.NoError(t, bitcoin.Publish(t.Context(), raw))
	require.NoError(t, bitcoin.Call(
		t.Context(), "generatetoaddress", []any{1, miner}, nil,
	))
	var signed wire.MsgTx
	require.NoError(t, signed.Deserialize(bytes.NewReader(raw)))
	output, err := bitcoin.UTXO(t.Context(), wire.OutPoint{
		Hash: signed.TxHash(),
	})
	require.NoError(t, err)
	require.Equal(t, coin.Output.Value-expirySweepFee, output.Output.Value)
	require.Positive(t, output.Confirmations)
}
