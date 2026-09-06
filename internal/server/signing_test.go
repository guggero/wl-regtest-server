package server

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/tree"
	"github.com/stretchr/testify/require"
)

// TestTreeSigning exercises independent client partials, durable nonce binding,
// malicious retries, and script-engine validation of complete transaction
// trees.
func TestTreeSigning(t *testing.T) {
	for _, count := range []int{1, 2, 7} {
		t.Run(string(rune('0'+count)), func(t *testing.T) {
			operator, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			sweep, err := btcec.NewPrivateKey()
			require.NoError(t, err)
			keys := make(map[string]*btcec.PrivateKey)
			var outputs []tree.VTXODescriptor
			for i := 0; i < count; i++ {
				key, err := btcec.NewPrivateKey()
				require.NoError(t, err)
				keys[hex.EncodeToString(
					key.PubKey().SerializeCompressed(),
				)] = key
				out, err := tree.NewVTXODescriptor(
					btcutil.Amount(10_000+i), key.PubKey(),
					operator.PubKey(), 10,
				)
				require.NoError(t, err)
				outputs = append(outputs, *out)
			}
			batch, err := tree.BuildBatchOutput(
				outputs, operator.PubKey(), sweep.PubKey(),
				1440,
			)
			require.NoError(t, err)
			virtual, err := tree.BuildVTXOTree(
				wire.OutPoint{
					Index: 1,
				}, batch, outputs, operator.PubKey(),
				sweep.PubKey(), 1440, 2,
			)
			require.NoError(t, err)
			fetcher, err := virtual.Root.PrevOutputFetcher(batch)
			require.NoError(t, err)
			for node := range virtual.Root.NodesIter() {
				digest, err := node.SigHash(fetcher)
				require.NoError(t, err)
				transcript, err := newNodeSigning(
					operator, digest,
				)
				require.NoError(t, err)
				clientNonces := make(map[string]*musig2.Nonces)
				public := make(map[string][]byte)
				for _, peer := range node.CoSigners {
					if peer.IsEqual(operator.PubKey()) {
						continue
					}
					id := hex.EncodeToString(
						peer.SerializeCompressed(),
					)
					nonce, err := musig2.GenNonces(
						musig2.WithPublicKey(peer),
					)
					require.NoError(t, err)
					clientNonces[id], public[id] = nonce, nonce.PubNonce[:]
				}
				require.NoError(t, transcript.bindNonces(
					operator, node, digest,
					virtual.SweepTapscriptRoot, public,
				))
				require.Empty(t, transcript.Secret)

				// Resume the transcript from its actual
				// persistent representation.
				raw, err := json.Marshal(transcript)
				require.NoError(t, err)
				var restored nodeSigning
				require.NoError(t, json.Unmarshal(
					raw, &restored,
				))
				require.NoError(t, restored.bindNonces(
					operator, node, digest,
					virtual.SweepTapscriptRoot, public,
				))
				partials := make(map[string][]byte)
				for id, nonce := range clientNonces {
					partial, err := musig2.Sign(
						nonce.SecNonce, keys[id],
						[musig2.PubNonceSize]byte(restored.Aggregate),
						node.CoSigners,
						[32]byte(digest),
						musig2.WithSortedKeys(),
						musig2.WithTaprootSignTweak(virtual.SweepTapscriptRoot),
					)
					require.NoError(t, err)
					var encoded bytes.Buffer
					require.NoError(t, partial.Encode(
						&encoded,
					))
					partials[id] = encoded.Bytes()
				}
				sig, err := restored.combine(
					operator.PubKey(), node, digest,
					virtual.SweepTapscriptRoot, partials,
				)
				require.NoError(t, err)
				node.AddSignature(sig)
				for id, nonce := range public {
					mutated := bytes.Clone(nonce)
					mutated[4] ^= 1
					public[id] = mutated
					require.ErrorContains(
						t,
						restored.bindNonces(operator, node, digest, virtual.SweepTapscriptRoot, public),
						"transcript changed",
					)
					break
				}
				for id, partial := range partials {
					partials[id] = bytes.Repeat([]byte{
						1,
					}, len(partial))
					_, err := restored.combine(
						operator.PubKey(), node, digest,
						virtual.SweepTapscriptRoot,
						partials,
					)
					require.Error(t, err)
					break
				}
			}
			require.NoError(t, virtual.ValidateValueConservation())
			require.NoError(t, virtual.VerifySigned())
			for node := range virtual.Root.NodesIter() {
				tx, err := node.ToSignedTx()
				require.NoError(t, err)
				require.NoError(t, verifyTransaction(
					tx, fetcher,
				))
			}
		})
	}
}
