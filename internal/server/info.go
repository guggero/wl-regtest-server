package server

import (
	"context"
	"slices"

	"github.com/lightninglabs/wavelength/arkrpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// GetInfo advertises the server's actual regtest identity and supported policy.
func (s *Server) GetInfo(_ context.Context,
	req *arkrpc.GetInfoRequest) (*arkrpc.GetInfoResponse, error) {

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.info(req), nil
}

// mailboxArk reuses the edge API while its dispatcher holds the state lock.
type mailboxArk struct{ *Server }

// GetInfo serves authenticated terms inside the mailbox transition.
func (m mailboxArk) GetInfo(_ context.Context,
	req *arkrpc.GetInfoRequest) (*arkrpc.GetInfoResponse, error) {

	return m.info(req), nil
}

// info snapshots advertised terms while the caller holds the state lock.
func (s *Server) info(req *arkrpc.GetInfoRequest) *arkrpc.GetInfoResponse {
	// Version zero signals no overlap; advertising terms must not silently
	// select version one when a client has not offered it.
	var selected uint32
	if slices.Contains(req.SupportedArkVersions, uint32(1)) {
		selected = 1
	}

	// Advertise the same limits the transaction handlers enforce. FeeRate
	// is a regtest estimate; the operator subsidizes actual mining costs
	// from its wallet.
	return &arkrpc.GetInfoResponse{
		Version: "wl-regtest-server/0.1", Pubkey: s.key.PubKey().SerializeCompressed(),
		Network: "regtest", BlockHeight: s.height,
		BoardingExitDelay: s.cfg.BoardingDelay,
		VtxoExitDelay:     s.cfg.ExitDelay, DustLimit: s.cfg.MinAmount,
		MinBoardingAmount: s.cfg.MinAmount, MinVtxoAmountSat: s.cfg.MinAmount,
		FeeRate: 1, MinConfirmations: 1, SelectedArkVersion: selected,
		FreeRefreshWindowBlocks: s.cfg.FreeRefreshWindow,
		ArkVersionPolicies: []*arkrpc.ArkVersionPolicy{{Version: 1,
			State: arkrpc.ArkVersionPolicy_STATE_ACTIVE}},
	}
}

// EstimateFee returns the zero-service-fee regtest quote and minimum viable
// output in satoshis. Positive amounts below that minimum receive a warning;
// nonpositive amounts are invalid. This does not reserve liquidity or guarantee
// that a later round can obtain wallet inputs.
func (s *Server) EstimateFee(_ context.Context,
	req *arkrpc.EstimateFeeRequest) (*arkrpc.EstimateFeeResponse, error) {

	if req.AmountSat <= 0 {
		return nil, status.Error(
			codes.InvalidArgument, "positive amount required",
		)
	}

	// An estimate may describe a sub-minimum payment so the client can
	// offer credit handling, even though an ordinary VTXO output would be
	// rejected.
	return &arkrpc.EstimateFeeResponse{
		MinViableAmountSat: s.cfg.MinAmount,
		BelowDustWarning:   req.AmountSat < s.cfg.MinAmount,
	}, nil
}
