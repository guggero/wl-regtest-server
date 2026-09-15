package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRefreshHeightFollowsNode proves admission reads the node's current tip
// rather than the worker loop's last sample, and keeps that sample while the
// node is unreachable so a transient RPC failure cannot fail a join.
func TestRefreshHeightFollowsNode(t *testing.T) {
	// Serve getblockchaininfo from mutable state so the test can advance
	// the chain and take the node down without touching the server.
	var blocks atomic.Uint32
	var down atomic.Bool
	node := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			var request struct {
				Method string `json:"method"`
			}
			if err := json.NewDecoder(
				r.Body,
			).Decode(
				&request,
			); err != nil || request.Method != "getblockchaininfo" {

				http.Error(
					w, "unexpected RPC",
					http.StatusBadRequest,
				)
				return
			}
			response := map[string]any{"result": nil}
			if down.Load() {
				response["error"] = map[string]any{
					"code":    -28,
					"message": "Loading block index",
				}
			} else {
				response["result"] = map[string]any{
					"chain":  "regtest",
					"blocks": blocks.Load(),
					"bestblockhash": blockHashAt(
						blocks.Load(),
					),
				}
			}
			_ = json.NewEncoder(w).Encode(response)
		},
	))
	defer node.Close()

	// Start from a sample the loop took one block ago, the state in which
	// a client that already saw the new block gets its proof rejected.
	s := testServer(t, t.TempDir())
	s.cfg.Bitcoin.URL = node.URL
	s.height, s.blockHash = 100, blockHashAt(100)
	blocks.Store(101)
	s.refreshHeight(t.Context())
	require.EqualValues(t, 101, s.height)
	require.Equal(t, blockHashAt(101), s.blockHash)

	// A node in warm-up must not zero the sample or otherwise regress it.
	down.Store(true)
	blocks.Store(102)
	s.refreshHeight(t.Context())
	require.EqualValues(t, 101, s.height)
	require.Equal(t, blockHashAt(101), s.blockHash)
}

// blockHashAt returns a distinct, well-formed block hash for a height.
func blockHashAt(height uint32) string {
	return fmt.Sprintf("%064x", height)
}
