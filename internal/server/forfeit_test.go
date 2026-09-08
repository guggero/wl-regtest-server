package server

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/google/uuid"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	arktx "github.com/lightninglabs/wavelength/lib/tx"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
)

// TestConnectorForfeits checks single-leaf and branched connector signatures
// and verifies a client's forfeit cannot redirect or inflate the penalty.
func TestConnectorForfeits(t *testing.T) {
	// Cover a degenerate connector tree, a branched tree, and a three-party
	// vHTLC leaf so the same penalty path is checked across signer
	// topologies.
	for _, test := range []struct {
		name   string
		count  int
		custom bool
	}{
		{name: "single-connector", count: 1},
		{name: "branched-connectors", count: 3},
		{name: "vhtlc-refund", count: 2, custom: true},
	} {

		t.Run(test.name, func(t *testing.T) {
			count := test.count
			s := testServer(t, t.TempDir())
			owner, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			policy, err := arkscript.StandardVTXOTemplate(
				owner.PubKey(), s.key.PubKey(), s.cfg.ExitDelay,
			)
			require.NoError(t, err)

			// The custom case adds a swap receiver share; ordinary
			// two-party forfeit compatibility must not omit that
			// required participant.
			var extra *btcec.PrivateKey
			var customPath *arkscript.SpendPath
			if test.custom {
				extra = s.deriveKey("swap-receiver/test")
				hash := sha256.Sum256([]byte("forfeit-refresh"))
				vhtlc, err := arkscript.NewVHTLCPolicy(
					arkscript.VHTLCOpts{
						Sender: owner.PubKey(), Receiver: extra.PubKey(), Server: s.key.PubKey(),
						PreimageHash: lntypes.Hash(
							hash,
						), RefundLocktime: 100,
						UnilateralClaimDelay: 10, UnilateralRefundDelay: 10,
						UnilateralRefundWithoutReceiverDelay: 20,
					},
				)
				require.NoError(t, err)
				policy = vhtlc.Template
				customPath, err = vhtlc.RefundPath()
				require.NoError(t, err)
			}
			rawPolicy, err := policy.Encode()
			require.NoError(t, err)
			script, err := policy.PkScript()
			require.NoError(t, err)
			var spend *arkscript.SpendPath
			if customPath != nil {
				spend = customPath
			} else {
				spend, _, err = standardPath(rawPolicy)
				require.NoError(t, err)
			}
			rawSpend, err := spend.Encode()
			require.NoError(t, err)

			// Model admitted inputs in request order so connector
			// assignment can be checked against the same round data
			// used by production validation.
			r := &roundRecord{
				ID:      uuid.NewString(),
				Request: &roundpb.JoinRoundRequest{},
				Batch:   &roundpb.ClientBatchInfo{},
			}
			for i := range count {
				r.Request.ForfeitRequests = append(
					r.Request.ForfeitRequests,
					&roundpb.ForfeitRequest{
						ForfeitSpendPath: rawSpend,
						VtxoOutpoint: &roundpb.Outpoint{
							TxHash: make(
								[]byte, 32,
							),
							OutputIndex: uint32(i),
						},
					},
				)
				r.Forfeits = append(r.Forfeits, &vtxoRecord{
					VTXO: &arkrpc.VTXO{
						ValueSat: 10000,
						PkScript: script,
					},
					Policy: rawPolicy,
				})
			}

			// Construct actual signed connector branches anchored
			// in one commitment before asking the client-side
			// builder for its conditional penalty.
			connectorScript, err := txscript.PayToTaprootScript(
				txscript.ComputeTaprootKeyNoScript(s.key.PubKey()),
			)
			require.NoError(t, err)
			commitment := wire.NewMsgTx(2)
			commitment.AddTxIn(wire.NewTxIn(
				&wire.OutPoint{}, nil, nil,
			))
			commitment.AddTxOut(wire.NewTxOut(
				int64(count)*connectorAmount, connectorScript,
			))
			require.NoError(t, s.buildConnectors(r, commitment, 0))
			previous := wire.OutPoint{}
			leaf := r.Batch.ConnectorLeafMap[previous.String()]
			connector, err := roundpb.OutpointFromProto(
				leaf.LeafOutpoint,
			)
			require.NoError(t, err)
			penalty, err := txscript.PayToTaprootScript(
				txscript.ComputeTaprootKeyNoScript(s.deriveKey(r.ID + "/forfeit").PubKey()),
			)
			require.NoError(t, err)
			tx, err := arktx.BuildForfeitTx(
				&previous, 10000, &connector, 330, penalty,
			)
			require.NoError(t, err)

			// Sign against both authoritative prevouts as a client
			// would; the server must complete a script-valid
			// penalty from these participant shares.
			packet, err := psbt.NewFromUnsignedTx(tx)
			require.NoError(t, err)
			packet.Inputs[0].WitnessUtxo = wire.NewTxOut(
				10000, script,
			)
			packet.Inputs[1].WitnessUtxo = wire.NewTxOut(
				330, connectorScript,
			)
			require.NoError(t, signPacketInput(
				packet, 0, owner, spend,
			))
			var raw bytes.Buffer
			require.NoError(t, tx.Serialize(&raw))
			submitted := &roundpb.ForfeitTxSig{UnsignedTx: raw.Bytes(), SpendPath: rawSpend,
				ClientVtxoSig: packet.Inputs[0].TaprootScriptSpendSig[0].Signature}
			if extra != nil {
				require.NoError(t, signPacketInput(
					packet, 0, extra, spend,
				))
				for i, key := range []*btcec.PrivateKey{
					owner, extra,
				} {

					submitted.ParticipantSigs = append(
						submitted.ParticipantSigs,
						&roundpb.ForfeitParticipantSig{
							Pubkey:    key.PubKey().SerializeCompressed(),
							Signature: packet.Inputs[0].TaprootScriptSpendSig[i].Signature,
						},
					)
				}
			}
			_, err = s.signForfeit(r, submitted, previous)
			require.NoError(t, err)

			// Legacy clients omit transaction context on their
			// standard forfeit path, which is equivalent to a final
			// sequence.
			spend.RequiredSequence = 0
			submitted.SpendPath, err = spend.Encode()
			require.NoError(t, err)
			_, err = s.signForfeit(r, submitted, previous)
			require.NoError(t, err)

			// A penalty with inflated output value must fail
			// structural validation even when it carries signatures
			// from an otherwise valid submission.
			tx.TxOut[0].Value++
			raw.Reset()
			require.NoError(t, tx.Serialize(&raw))
			submitted.UnsignedTx = raw.Bytes()
			_, err = s.signForfeit(r, submitted, previous)
			require.ErrorContains(t, err, "incorrect forfeit value")
		})
	}
}
