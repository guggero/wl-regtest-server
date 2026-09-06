package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/stretchr/testify/require"
)

// TestUnilateralPreimageRecovery recovers a hashlock from the exact Bitcoin
// input after an operator outage, and retains it across a process restart.
func TestUnilateralPreimageRecovery(t *testing.T) {
	preimage := sha256.Sum256([]byte("unilateral-receive"))
	hash := sha256.Sum256(preimage[:])
	txid := hex.EncodeToString(make([]byte, 32))
	outpoint := txid + ":3"
	node := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				Method string `json:"method"`
			}
			if err := json.NewDecoder(
				r.Body,
			).Decode(
				&request,
			); err != nil {

				http.Error(
					w, err.Error(), 400,
				)
				return
			}
			var result any
			switch request.Method {
			case "gettxspendingprevout":
				result = []any{}

			case "getblockhash":
				result = "canonical-block"

			case "getblock":
				result = map[string]any{"tx": []any{map[string]any{
					"txid": "spending-transaction", "vin": []any{
						map[string]any{
							"txid": txid,
							"vout": 4,
							"txinwitness": []string{
								hex.EncodeToString(preimage[:]),
							},
						},
						map[string]any{
							"txid": txid,
							"vout": 3,
							"txinwitness": []string{
								hex.EncodeToString(make([]byte, 32)),
								hex.EncodeToString(preimage[:]),
							},
						},
					},
				}}}

			default:
				http.Error(w, "unexpected RPC", 400)
				return
			}
			_ = json.NewEncoder(
				w,
			).Encode(map[string]any{
				"result": result,
			})
		},
	))
	defer node.Close()
	dir := t.TempDir()
	s := testServer(t, dir)
	s.height = 101
	s.cfg.Bitcoin.URL = node.URL
	require.NoError(t, s.transact(t.Context(), func() error {
		if err := s.put(
			"vtxo/"+outpoint, &vtxoRecord{VTXO: &arkrpc.VTXO{
				Outpoint: &arkrpc.OutPoint{
					Txid: make(
						[]byte, 32,
					),
					Vout: 3,
				},
				CreatedHeight: 100, Status: arkrpc.VTXOStatus_VTXO_STATUS_UNILATERAL_EXIT,
			}},
		); err != nil {

			return err
		}
		return s.put(
			"out-swap/test",
			&outSwap{Phase: "funded", Outpoint: outpoint,
				Request: &swaprpc.RequestChannelIdRequest{
					PaymentHash: hash[:],
				},
			},
		)
	}))
	require.NoError(t, s.pollSwapChain(t.Context()))
	found, err := s.observedPreimage(outpoint, hash[:])
	require.NoError(t, err)
	require.Equal(t, preimage[:], found)
	require.NoError(t, s.Stop())
	s = testServer(t, dir)
	found, err = s.observedPreimage(outpoint, hash[:])
	require.NoError(t, err)
	require.Equal(t, preimage[:], found)
	wrong := sha256.Sum256([]byte("other hash"))
	found, err = s.observedPreimage(outpoint, wrong[:])
	require.NoError(t, err)
	require.Empty(t, found)
	found, err = s.observedPreimage(txid+":4", hash[:])
	require.NoError(t, err)
	require.Empty(t, found)
}
