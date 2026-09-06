package server

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/tx/psbtutil"
	"github.com/stretchr/testify/require"
)

// TestInventoryCanonicalFunding spends distinct treasury keys through the full
// OOR signing path and verifies that small change remains correctly indexed
// when the public builder sorts both checkpoint inputs and recipient outputs.
func TestInventoryCanonicalFunding(t *testing.T) {
	s := testServer(t, t.TempDir())
	var inputs []wire.OutPoint
	for i := range 8 {
		domain := fmt.Sprintf("inventory/test/%d", i)
		policy, err := arkscript.StandardVTXOTemplate(
			s.deriveKey(domain).PubKey(), s.key.PubKey(),
			s.cfg.ExitDelay,
		)
		require.NoError(t, err)
		raw, err := policy.Encode()
		require.NoError(t, err)
		script, err := policy.PkScript()
		require.NoError(t, err)
		op := wire.OutPoint{Index: uint32(i)}
		op.Hash[0] = byte(i + 1)
		inputs = append(inputs, op)
		require.NoError(t, s.put(
			"inventory-script/"+hex.EncodeToString(script), domain,
		))
		require.NoError(t, s.put("vtxo/"+op.String(), &vtxoRecord{
			Policy: raw,
			VTXO: &arkrpc.VTXO{
				Outpoint: &arkrpc.OutPoint{
					Txid: op.Hash[:],
					Vout: op.Index,
				},
				ValueSat: 10000, PkScript: script,
				Status:            arkrpc.VTXOStatus_VTXO_STATUS_LIVE,
				BatchExpiryHeight: 1440,
			},
		}))
	}
	policy, err := arkscript.StandardVTXOTemplate(
		s.deriveKey("recipient").PubKey(), s.key.PubKey(),
		s.cfg.ExitDelay,
	)
	require.NoError(t, err)
	raw, err := policy.Encode()
	require.NoError(t, err)
	script, err := policy.PkScript()
	require.NoError(t, err)
	var funding *inventoryFunding
	require.NoError(t, s.transact(t.Context(), func() error {
		var err error
		funding, err = s.fundInventoryOutput(t.Context(), raw, 75000)
		return err
	}))
	require.NotNil(t, funding)
	require.EqualValues(t, 1, funding.Outpoint.Index)
	require.Equal(t, funding.Session, funding.Outpoint.Hash.String())
	record, err := get[oorRecord](s, "oor/"+funding.Session)
	require.NoError(t, err)
	require.NotNil(t, record)
	require.Len(t, record.Final, 1)
	packet, err := psbtutil.Parse(record.Final[0].ArkPsbt)
	require.NoError(t, err)
	tx, err := signedPacket(packet)
	require.NoError(t, err)
	require.Len(t, tx.TxIn, len(inputs))
	require.EqualValues(t, 5000, tx.TxOut[0].Value)
	require.EqualValues(t, 75000, tx.TxOut[1].Value)
	require.Equal(t, script, tx.TxOut[1].PkScript)
	for i := range 2 {
		op := wire.OutPoint{Hash: tx.TxHash(), Index: uint32(i)}
		output, err := get[vtxoRecord](s, "vtxo/"+op.String())
		require.NoError(t, err)
		require.NotNil(t, output)
		require.EqualValues(t, tx.TxOut[i].Value, output.VTXO.ValueSat)
		require.Equal(t, tx.TxOut[i].PkScript, output.VTXO.PkScript)
	}
	for _, op := range inputs {
		input, err := get[vtxoRecord](s, "vtxo/"+op.String())
		require.NoError(t, err)
		require.Equal(
			t, arkrpc.VTXOStatus_VTXO_STATUS_SPENT,
			input.VTXO.Status,
		)
	}
}
