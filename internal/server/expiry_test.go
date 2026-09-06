package server

import (
	"testing"
	"time"

	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestUnfundedCreditExpiry releases an abandoned quote exactly once while
// preserving the reservation of a Lightning payment with an ambiguous result.
func TestUnfundedCreditExpiry(t *testing.T) {
	s := testServer(t, t.TempDir())
	now := time.Unix(1800000000, 0)
	clk := clock.NewTestClock(now)
	s.cfg.Clock = clk
	require.NoError(t, s.transact(t.Context(), func() error {
		if err := s.put("credit-account/test", &creditAccount{
			Finalized: 10000,
			Reserved:  2000,
		}); err != nil {

			return err
		}
		for _, phase := range []string{"awaiting-funding", "paying"} {
			id := "expiry/" + phase
			record := &creditRecord{Account: "test", Operation: &swaprpc.CreditOperation{
				OperationId: id, AmountSat: 1000, State: swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_RESERVED,
			}}
			if err := s.put(
				"credit-operation/"+id, record,
			); err != nil {

				return err
			}
			if err := s.put(
				"in-swap/"+phase,
				&inSwap{Phase: phase, CreditID: id, Account: "test", Response: &swaprpc.CreateInSwapResponse{
					Expiry: timestamppb.New(now.Add(
						time.Minute,
					)),
				}},
			); err != nil {

				return err
			}
		}
		return nil
	}))
	require.NoError(t, s.expireAwaitingSwaps(t.Context()))
	account, err := s.account("test")
	require.NoError(t, err)
	require.EqualValues(t, 2000, account.Reserved)
	clk.SetTime(now.Add(time.Minute))
	for range 2 {
		require.NoError(t, s.expireAwaitingSwaps(t.Context()))
	}
	account, err = s.account("test")
	require.NoError(t, err)
	require.EqualValues(t, 1000, account.Reserved)
	require.EqualValues(t, 10000, account.Finalized)
	expired, err := get[inSwap](s, "in-swap/awaiting-funding")
	require.NoError(t, err)
	require.Equal(t, "failed", expired.Phase)
	paying, err := get[inSwap](s, "in-swap/paying")
	require.NoError(t, err)
	require.Equal(t, "paying", paying.Phase)
}
