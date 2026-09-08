package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFreshIdentityRecovery preserves the advertised identity even when the
// process stops before admitting its first protocol request.
func TestFreshIdentityRecovery(t *testing.T) {
	// Stop before any protocol request could force a snapshot, exercising
	// the constructor's obligation to save the newly advertised seed
	// immediately.
	dir := t.TempDir()
	s := testServer(t, dir)
	identity := s.id
	key := s.deriveKey("unused-swap").Serialize()
	require.Empty(t, s.Address())
	require.NoError(t, s.Stop())
	require.NoError(t, s.Stop())
	require.ErrorContains(t, s.Start(t.Context()), "already")

	// Restoration must reproduce both public identity and unrelated derived
	// keys, proving that the seed itself survived the early shutdown.
	restored := testServer(t, dir)
	require.Equal(t, identity, restored.id)
	require.Equal(t, key, restored.deriveKey("unused-swap").Serialize())
}
