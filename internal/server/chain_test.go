package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/stretchr/testify/require"
)

// TestChainReconciliation exercises authoritative reorg and unilateral-spend
// observations while preserving already-consumed VTXOs across reconfirmation.
func TestChainReconciliation(t *testing.T) {
	var state atomic.Int32
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
					w, err.Error(),
					http.StatusBadRequest,
				)
				return
			}
			var result any
			switch request.Method {
			case "gettxout":
				if state.Load() != 2 {
					confs := 1
					if state.Load() == 1 {
						confs = 0
					}
					result = map[string]any{"value": 0.001,
						"confirmations": confs, "scriptPubKey": map[string]string{
							"hex": "5120",
						}}
				}

			case "getrawtransaction":
				result = map[string]int{
					"confirmations": 1,
				}

			default:
				http.Error(
					w, "unexpected RPC",
					http.StatusBadRequest,
				)
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
	s := testServer(t, t.TempDir())
	s.cfg.Bitcoin.URL = node.URL
	record := &vtxoRecord{VTXO: &arkrpc.VTXO{
		Status:            arkrpc.VTXOStatus_VTXO_STATUS_LIVE,
		BatchExpiryHeight: 1440,
		AncestryPaths: []*arkrpc.AncestryPath{{TreePath: &arkrpc.TreePath{
			BatchOutpoint: &arkrpc.OutPoint{Txid: make([]byte, 32)},
		}}},
	}}
	require.NoError(t, s.transact(t.Context(), func() error {
		if err := s.recordVTXO("vtxo/live", record, 0); err != nil {
			return err
		}
		record.VTXO.Status = arkrpc.VTXOStatus_VTXO_STATUS_SPENT
		return s.recordVTXO("vtxo/spent", record, 0)
	}))
	for _, test := range []struct {
		name   string
		chain  int32
		status arkrpc.VTXOStatus
	}{
		{"disconnected", 1, arkrpc.VTXOStatus_VTXO_STATUS_UNCONFIRMED},
		{"reconfirmed", 0, arkrpc.VTXOStatus_VTXO_STATUS_LIVE},
		{"unrolled", 2, arkrpc.VTXOStatus_VTXO_STATUS_UNILATERAL_EXIT},
		{"unroll-reverted", 0, arkrpc.VTXOStatus_VTXO_STATUS_LIVE},
	} {

		t.Run(test.name, func(t *testing.T) {
			state.Store(test.chain)
			require.NoError(t, s.pollVTXOChain(t.Context()))
			live, err := get[vtxoRecord](s, "vtxo/live")
			require.NoError(t, err)
			require.Equal(t, test.status, live.VTXO.Status)
			spent, err := get[vtxoRecord](s, "vtxo/spent")
			require.NoError(t, err)
			require.Equal(
				t, arkrpc.VTXOStatus_VTXO_STATUS_SPENT,
				spent.VTXO.Status,
			)
			before := live.EventID
			require.NoError(t, s.pollVTXOChain(t.Context()))
			live, err = get[vtxoRecord](s, "vtxo/live")
			require.NoError(t, err)
			require.Equal(t, before, live.EventID)
		})
	}
}
