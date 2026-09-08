package server

import (
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	oortx "github.com/lightninglabs/wavelength/lib/tx/oor"
	"github.com/lightninglabs/wavelength/lib/tx/psbtutil"
	"github.com/lightninglabs/wavelength/rpc/oorpb"
	"github.com/stretchr/testify/require"
)

// TestOORSigningAndValidation verifies authoritative value binding, operator
// checkpoint construction, and script execution with both parties' signatures.
func TestOORSigningAndValidation(t *testing.T) {
	// Create a real standard policy and indexed input, keeping
	// authoritative value separate from the PSBT metadata that the client
	// submits.
	s := testServer(t, t.TempDir())
	owner, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	policy, err := arkscript.StandardVTXOTemplate(
		owner.PubKey(), s.key.PubKey(), s.cfg.ExitDelay,
	)
	require.NoError(t, err)
	rawPolicy, err := policy.Encode()
	require.NoError(t, err)
	script, err := policy.PkScript()
	require.NoError(t, err)
	spend, _, err := standardPath(rawPolicy)
	require.NoError(t, err)
	rawSpend, err := spend.Encode()
	require.NoError(t, err)
	leaf := arkscript.LeafTemplate{
		Node: &arkscript.Multisig{
			Keys: []*btcec.PublicKey{
				owner.PubKey(), s.key.PubKey(),
			},
		},
	}
	rawLeaf, err := leaf.Encode()
	require.NoError(t, err)
	prev := wire.OutPoint{Index: 1}
	previous := wire.NewTxOut(10000, script)
	record := &vtxoRecord{VTXO: &arkrpc.VTXO{ValueSat: 10000, PkScript: script,
		Status: arkrpc.VTXOStatus_VTXO_STATUS_LIVE, BatchExpiryHeight: 1440}, Policy: rawPolicy}
	require.NoError(t, s.put("vtxo/"+prev.String(), record))

	// Use public builders for the checkpoint and Ark stage so validation
	// checks protocol-compatible construction rather than handcrafted
	// placeholders.
	checkpoint, err := oortx.BuildCheckpointPSBT(
		arkscript.CheckpointPolicy{
			OperatorKey: s.key.PubKey(), CSVDelay: 10,
		}, oortx.CheckpointInput{
			SpentVTXO: oortx.SpentVTXORef{
				Outpoint: prev,
				Output:   previous,
			},
			OwnerLeafPolicy: rawLeaf,
		},
	)
	require.NoError(t, err)
	output, err := checkpoint.ToCheckpointOutput()
	require.NoError(t, err)
	recipients := []oortx.RecipientOutput{
		{
			PkScript:           script,
			Value:              10000,
			VTXOPolicyTemplate: rawPolicy,
		},
	}
	ark, err := oortx.BuildArkPSBT([]oortx.CheckpointOutput{
		output,
	}, recipients)
	require.NoError(t, err)
	packets := []*psbt.Packet{checkpoint.PSBT}
	descriptors := []oorpb.SigningDescriptor{
		{
			Outpoint:           prev,
			VTXOPolicyTemplate: rawPolicy,
			SpendPath:          rawSpend,
			OwnerLeafPolicy:    rawLeaf,
		},
	}

	// Complete the Ark stage and round-trip its PSBT serialization to catch
	// duplicate metadata or signatures that cannot survive the wire format.
	inputs, err := s.validateOOR(ark, packets, descriptors, recipients)
	require.NoError(t, err)
	bound := inputs[checkpoint.PSBT.UnsignedTx.TxHash()]
	require.NoError(t, signPacketInput(ark, 0, owner, bound.ArkSpend))
	require.NoError(t, signPacketInput(ark, 0, s.key, bound.ArkSpend))
	encoded, err := psbtutil.Serialize(ark)
	require.NoError(t, err)
	ark, err = psbtutil.Parse(encoded)
	require.NoError(t, err)
	_, err = oortx.ValidateSubmitPackageSigned(ark, packets)
	require.NoError(t, err)

	// An operator share alone cannot spend the checkpoint. Only adding the
	// owner share should make final witness execution succeed.
	require.NoError(t, signPacketInput(checkpoint.PSBT, 0, s.key, spend))
	_, err = signedPacket(checkpoint.PSBT)
	require.Error(t, err)
	require.NoError(t, signPacketInput(checkpoint.PSBT, 0, owner, spend))
	require.NoError(t, oortx.ValidateFinalizePackageSigned(ark, packets))
	_, err = signedPacket(checkpoint.PSBT)
	require.NoError(t, err)

	// A fully signed package still cannot override indexed value or spent
	// status; alter authoritative state to exercise both admission
	// boundaries.
	record.VTXO.ValueSat--
	require.NoError(t, s.put("vtxo/"+prev.String(), record))
	_, err = s.validateOOR(ark, packets, descriptors, recipients)
	require.ErrorContains(t, err, "authoritative VTXO")
	record.VTXO.ValueSat++
	record.VTXO.Status = arkrpc.VTXOStatus_VTXO_STATUS_SPENT
	require.NoError(t, s.put("vtxo/"+prev.String(), record))
	_, err = s.validateOOR(ark, packets, descriptors, recipients)
	require.ErrorContains(t, err, "not spendable")
}
