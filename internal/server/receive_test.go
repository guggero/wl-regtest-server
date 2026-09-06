package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/lightningnetwork/lnd/clock"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lntypes"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestReceiveCircuitAdmission exercises multipart aggregation, exact circuit
// replay, hash and amount binding, and the signed acknowledgement funding gate.
func TestReceiveCircuitAdmission(t *testing.T) {
	s := testServer(t, t.TempDir())
	s.interceptorReady = true
	s.lndPubkey = s.deriveKey("test-lnd").PubKey().SerializeCompressed()
	receiver, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	hash := sha256.Sum256([]byte("test preimage"))
	request := &swaprpc.RequestChannelIdRequest{
		ClientVhtlcPubkey: receiver.PubKey().SerializeCompressed(),
		PaymentHash:       hash[:],
		AmountSat:         10000,
		ExpirySeconds:     uint32(time.Hour / time.Second),
	}
	signCreditRequest(t, s, receiver, request)
	route, err := s.RequestChannelId(context.Background(), request)
	require.NoError(t, err)
	channel := route.RouteHintPaths[0].Hops[0].ChannelId
	first := &routerrpc.ForwardHtlcInterceptRequest{IncomingCircuitKey: &routerrpc.CircuitKey{
		ChanId: 42,
		HtlcId: 1,
	}, PaymentHash: hash[:], IncomingAmountMsat: 4000000, OutgoingAmountMsat: 4000000,
		IncomingExpiry: 600, OutgoingExpiry: 300, AutoFailHeight: 570, OutgoingRequestedChanId: channel, OnionBlob: make([]byte, 1366)}
	resp, err := s.acceptIntercept(context.Background(), first)
	require.NoError(t, err)
	require.Nil(t, resp)
	r, err := get[outSwap](s, "out-swap/"+hex.EncodeToString(hash[:]))
	require.NoError(t, err)
	require.Equal(t, "collecting", r.Phase)
	require.Nil(t, r.Config)
	resp, err = s.acceptIntercept(context.Background(), first)
	require.NoError(t, err)
	require.Nil(t, resp)
	oversized := proto.Clone(first).(*routerrpc.ForwardHtlcInterceptRequest)
	oversized.IncomingCircuitKey.HtlcId = 2
	oversized.OutgoingAmountMsat = 7000000
	oversized.IncomingAmountMsat = 7000000
	resp, err = s.acceptIntercept(context.Background(), oversized)
	require.NoError(t, err)
	require.Equal(t, routerrpc.ResolveHoldForwardAction_FAIL, resp.Action)
	second := proto.Clone(
		oversized,
	).(*routerrpc.ForwardHtlcInterceptRequest)
	second.OutgoingAmountMsat = 6000000
	second.IncomingAmountMsat = 6000000
	resp, err = s.acceptIntercept(context.Background(), second)
	require.NoError(t, err)
	require.Nil(t, resp)
	r, err = get[outSwap](s, "out-swap/"+hex.EncodeToString(hash[:]))
	require.NoError(t, err)
	require.Equal(t, "awaiting-ack", r.Phase)
	require.Len(t, r.Circuits, 2)
	require.Empty(t, r.Session)
	ack := &swaprpc.AcknowledgeOutSwapHtlcRequest{
		PaymentHash:       hash[:],
		ClientVhtlcPubkey: receiver.PubKey().SerializeCompressed(),
	}
	_, err = s.AcknowledgeOutSwapHtlc(context.Background(), ack)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	digest := swaprpc.OutSwapHTLCAckDigest(
		receiver.PubKey(), lntypes.Hash(hash), 10000, r.Script,
	)
	signature, err := schnorr.Sign(receiver, digest[:])
	require.NoError(t, err)
	ack.AcknowledgementSignature = signature.Serialize()
	_, err = s.AcknowledgeOutSwapHtlc(context.Background(), ack)
	require.NoError(t, err)
	r, err = get[outSwap](s, "out-swap/"+hex.EncodeToString(hash[:]))
	require.NoError(t, err)
	require.Equal(t, "acknowledged", r.Phase)
	require.Empty(t, r.Session)

	// Missing replayed circuits cannot trigger funding after a reconnect.
	_, err = s.reconcileReceives(context.Background(), map[string]bool{})
	require.NoError(t, err)
	r, err = get[outSwap](s, "out-swap/"+hex.EncodeToString(hash[:]))
	require.NoError(t, err)
	require.Empty(t, r.Session)

	// An expired acknowledgement must fail before treasury selection, even
	// when all circuits replay after reconnecting to LND.
	s.cfg.Clock = clock.NewTestClock(s.cfg.Clock.Now().Add(2 * time.Hour))
	responses, err := s.reconcileReceives(
		context.Background(), map[string]bool{
			circuitID(first.IncomingCircuitKey):  true,
			circuitID(second.IncomingCircuitKey): true,
		},
	)
	require.NoError(t, err)
	require.Len(t, responses, 2)
	for _, response := range responses {
		require.Equal(
			t, routerrpc.ResolveHoldForwardAction_FAIL,
			response.Action,
		)
	}
	r, err = get[outSwap](s, "out-swap/"+hex.EncodeToString(hash[:]))
	require.NoError(t, err)
	require.Equal(t, "failed", r.Phase)
	require.Empty(t, r.Session)
}
