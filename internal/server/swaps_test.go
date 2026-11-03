package server

import (
	"testing"

	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/stretchr/testify/require"
)

// TestQuoteSettlement checks the funding path a pay quote previews. In
// particular, a dust invoice from a wallet with no credit yet must preview
// credit settlement: the client tops up and then pays from credit, and it
// rejects a quote that funds nothing through any other path.
func TestQuoteSettlement(t *testing.T) {
	t.Parallel()

	s := &Server{cfg: DefaultConfig()}
	tests := []struct {
		name               string
		amount, available  uint64
		maximum            uint64
		sameArk            bool
		want               swaprpc.SettlementType
		wantArkFundingZero bool
	}{{
		name:   "dust without credit tops up",
		amount: 500, maximum: 500,
		want:               swaprpc.SettlementType_SETTLEMENT_TYPE_CREDIT,
		wantArkFundingZero: true,
	}, {
		name:   "dust without credit to the same Ark",
		amount: 500, maximum: 500, sameArk: true,
		want:               swaprpc.SettlementType_SETTLEMENT_TYPE_CREDIT,
		wantArkFundingZero: true,
	}, {
		name:   "dust covered by credit",
		amount: 500, available: 800, maximum: 500,
		want:               swaprpc.SettlementType_SETTLEMENT_TYPE_CREDIT,
		wantArkFundingZero: true,
	}, {
		name:   "partly covered by credit",
		amount: 5_000, available: 2_000, maximum: 5_000,
		want: swaprpc.SettlementType_SETTLEMENT_TYPE_MIXED,
	}, {
		name:   "no credit authorized",
		amount: 5_000, available: 2_000,
		want: swaprpc.SettlementType_SETTLEMENT_TYPE_LIGHTNING,
	}, {
		name:   "no credit to the same Ark",
		amount: 5_000, sameArk: true,
		want: swaprpc.SettlementType_SETTLEMENT_TYPE_IN_ARK,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			quote := s.creditQuote(tc.amount, tc.available, tc.maximum)
			require.Equal(
				t, tc.want,
				quoteSettlement(tc.amount, quote, tc.sameArk),
			)
			require.Equal(
				t, tc.wantArkFundingZero, quote.ArkFundingSat == 0,
			)
		})
	}
}
