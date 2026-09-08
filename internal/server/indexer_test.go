package server

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btclog/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/indexer"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/fn/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestIndexerProofCompatibility verifies public-client TLV proofs, including
// participant binding, cross-purpose rejection, and the signed expiry window.
func TestIndexerProofCompatibility(t *testing.T) {
	// Generate the scope proof through the upstream indexer client so the
	// test checks wire compatibility independently of the server verifier.
	s := testServer(t, t.TempDir())
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	policy, err := arkscript.StandardVTXOTemplate(
		key.PubKey(), s.key.PubKey(), s.cfg.ExitDelay,
	)
	require.NoError(t, err)
	script, err := policy.PkScript()
	require.NoError(t, err)
	ctx := context.WithValue(
		context.Background(), principalKey{}, "test-principal",
	)
	client := indexer.New(
		nil, &indexer.PrivKeySchnorrSigner{Key: key},
		indexerProofServerID, principal(ctx), fn.None[btclog.Logger](),
	)
	req, err := client.BuildListVTXOsByScriptsTaprootRequest(
		ctx, []indexer.TaprootScriptScope{{PkScript: script}}, nil, 10,
		nil,
	)
	require.NoError(t, err)
	resp, err := s.ListVTXOsByScripts(ctx, req)
	require.NoError(t, err)
	require.Empty(t, resp.Vtxos)

	// The same valid query proof must not authorize registration or access
	// to a script owned by another participant.
	proof := req.Scripts[0].GetTaprootSchnorr()
	err = s.verifyScriptProof(ctx, script, proof, "register_receive_script")
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	other, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	otherPolicy, err := arkscript.StandardVTXOTemplate(
		other.PubKey(), s.key.PubKey(), s.cfg.ExitDelay,
	)
	require.NoError(t, err)
	otherScript, err := otherPolicy.PkScript()
	require.NoError(t, err)
	err = s.verifyScriptProof(
		ctx, otherScript, proof, "list_vtxos_by_scripts",
	)
	require.Equal(t, codes.PermissionDenied, status.Code(err))

	// Mailbox identity and validity window are also signed scope: neither a
	// different principal nor an expired clock may reuse the proof.
	foreign := context.WithValue(ctx, principalKey{}, "another-principal")
	_, err = s.ListVTXOsByScripts(foreign, req)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	s.cfg.Clock = clock.NewTestClock(time.Now().Add(11 * time.Minute))
	_, err = s.ListVTXOsByScripts(ctx, req)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
}

// TestIndexerEventRecovery verifies that catch-up events and push delivery
// survive restart without generating duplicate events when a round is
// rescanned.
func TestIndexerEventRecovery(t *testing.T) {
	// Create one registered recipient and one live VTXO so the state change
	// produces both durable catch-up history and a mailbox notification.
	dir := t.TempDir()
	s := testServer(t, dir)
	ctx := context.Background()
	script := append([]byte{0x51, 0x20}, make([]byte, 32)...)
	record := &vtxoRecord{VTXO: &arkrpc.VTXO{
		PkScript: script, ValueSat: 10000,
		Status:        arkrpc.VTXOStatus_VTXO_STATUS_LIVE,
		CreatedHeight: 100, BatchExpiryHeight: 1540,
	}}
	err := s.transact(ctx, func() error {
		if err := s.put(
			registrationKey("receiver", script),
			&registeredScript{Owner: "receiver",
				Script: &arkrpc.RegisteredReceiveScript{
					PkScript: script,
				},
			},
		); err != nil {

			return err
		}
		return s.recordVTXO(
			"vtxo/test", record,
			arkrpc.VTXOOrigin_VTXO_ORIGIN_IN_ROUND,
		)
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, record.EventID)
	require.Len(t, s.state.Mail["receiver"].Messages, 1)

	// Reindex unchanged data after restart to ensure recovery preserves the
	// original event ID and does not enqueue a duplicate notification.
	require.NoError(t, s.Stop())
	s = testServer(t, dir)
	err = s.transact(ctx, func() error {
		return s.recordVTXO(
			"vtxo/test", record,
			arkrpc.VTXOOrigin_VTXO_ORIGIN_IN_ROUND,
		)
	})
	require.NoError(t, err)
	require.EqualValues(t, 1, record.EventID)
	require.Len(t, s.state.Mail["receiver"].Messages, 1)

	// An actual expiry change must produce a new event, distinguishing
	// meaningful lifecycle updates from idempotent rescans.
	record.VTXO.BatchExpiryHeight++
	err = s.transact(ctx, func() error {
		return s.recordVTXO(
			"vtxo/test", record,
			arkrpc.VTXOOrigin_VTXO_ORIGIN_IN_ROUND,
		)
	})
	require.NoError(t, err)
	require.EqualValues(t, 2, record.EventID)
	require.Len(t, s.state.Mail["receiver"].Messages, 2)
}
