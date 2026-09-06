package server

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/arkrpc"
	mailboxpb "github.com/lightninglabs/wavelength/mailbox/pb"
	"github.com/lightninglabs/wavelength/serverconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// testServer restores an offline server without starting backend workers.
func testServer(t *testing.T, dir string) *Server {
	t.Helper()
	cfg := DefaultConfig()
	cfg.DataDir = dir
	cfg.Bitcoin, cfg.LND = &backend.Bitcoin{}, &backend.LND{}
	s, err := New(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Stop()) })
	return s
}

// TestMailboxClientEvents exercises the public actor's one-way envelope shape,
// including its absent correlation ID and heartbeat's absent body.
func TestMailboxClientEvents(t *testing.T) {
	dir := t.TempDir()
	s := testServer(t, dir)
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	id := serverconn.PubKeyMailboxID(key.PubKey())
	target := serverconn.CompoundMailboxID(s.id, id)
	body, err := anypb.New(wrapperspb.String("event"))
	require.NoError(t, err)
	req := &mailboxpb.SendRequest{Envelope: &mailboxpb.Envelope{
		ProtocolVersion: 1, ArkProtocolVersion: 1, Sender: id,
		Recipient: target, IdempotencyKey: "event-1", Body: body,
		Rpc: &mailboxpb.RpcMeta{Kind: mailboxpb.RpcMeta_KIND_EVENT,
			Service: "test", Method: "Apply", ReplyTo: id},
	}}
	_, err = s.Send(mailboxContext(t, key, target), req)
	require.NoError(t, err)
	require.NoError(t, s.Stop())
	s = testServer(t, dir)
	executed := 0
	s.router.Handle("test", "Apply", func() proto.Message {
		return &wrapperspb.StringValue{}
	}, func(ctx context.Context, msg proto.Message) (proto.Message, error) {
		executed++
		return msg, s.emit(principal(ctx), "test", "Applied", msg)
	})
	require.NoError(t, s.dispatchPending(t.Context()))
	_, err = s.Send(mailboxContext(t, key, target), req)
	require.NoError(t, err)
	require.NoError(t, s.dispatchPending(t.Context()))
	require.Equal(t, 1, executed)
	require.Len(t, s.state.Mail[id].Messages, 1)
	heartbeat := proto.Clone(req).(*mailboxpb.SendRequest)
	heartbeat.Envelope.Body = nil
	heartbeat.Envelope.IdempotencyKey = ""
	heartbeat.Envelope.Rpc.Service = serverconn.HeartbeatService
	heartbeat.Envelope.Rpc.Method = serverconn.HeartbeatMethod
	_, err = s.Send(mailboxContext(t, key, target), heartbeat)
	require.NoError(t, err)
	require.Len(t, s.state.Requests, 1)
	info, err := marshal(&arkrpc.GetInfoRequest{
		SupportedArkVersions: []uint32{
			1,
		},
	})
	require.NoError(t, err)
	err = s.transact(t.Context(), func() error {
		result, err := s.router.ServeRPC(
			t.Context(), "arkrpc.ArkService", "GetInfo", info,
		)
		if err != nil {
			return err
		}
		require.EqualValues(
			t, 1,
			result.(*arkrpc.GetInfoResponse).SelectedArkVersion,
		)
		return nil
	})
	require.NoError(t, err)
}

// mailboxContext authenticates an exact destination with an independent key.
func mailboxContext(t *testing.T, key *btcec.PrivateKey,
	recipient string) context.Context {

	t.Helper()
	sig, err := serverconn.SignMailboxAuth(key, recipient)
	require.NoError(t, err)
	return metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		serverconn.AuthHeaderKey, hex.EncodeToString(sig.Serialize()),
	))
}

// TestMailboxRecovery proves an admitted request survives process replacement,
// executes once, and retains replay protection after its response is
// acknowledged.
func TestMailboxRecovery(t *testing.T) {
	dir := t.TempDir()
	s := testServer(t, dir)
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	id := serverconn.PubKeyMailboxID(key.PubKey())
	target := serverconn.CompoundMailboxID(s.id, id)
	body, err := anypb.New(wrapperspb.String("credit-once"))
	require.NoError(t, err)
	req := &mailboxpb.SendRequest{Envelope: &mailboxpb.Envelope{
		ProtocolVersion: 1, ArkProtocolVersion: 1, Sender: id, Recipient: target,
		IdempotencyKey: "operation-1", Body: body,
		Rpc: &mailboxpb.RpcMeta{
			Kind:          mailboxpb.RpcMeta_KIND_REQUEST,
			CorrelationId: "call-1",
			ReplyTo:       id,
			Service:       "test",
			Method:        "Apply",
		},
	}}
	_, err = s.Send(context.Background(), req)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = s.Send(mailboxContext(t, key, target), req)
	require.NoError(t, err)
	require.NoError(t, s.Stop())
	s = testServer(t, dir)
	executed := 0
	s.router.Handle(
		"test", "Apply", func() proto.Message {
			return &wrapperspb.StringValue{}
		},
		func(ctx context.Context, msg proto.Message) (proto.Message,
			error) {

			executed++
			return msg, s.put("effect", principal(ctx))
		},
	)
	require.NoError(t, s.dispatchPending(context.Background()))
	readCtx := mailboxContext(t, key, id)
	pulled, err := s.Pull(readCtx, &mailboxpb.PullRequest{MailboxId: id})
	require.NoError(t, err)
	require.Len(t, pulled.Envelopes, 1)
	require.Equal(t, uint64(2), pulled.NextCursor)
	_, err = s.AckUpTo(readCtx, &mailboxpb.AckUpToRequest{
		MailboxId: id,
		Cursor:    pulled.NextCursor,
	})
	require.NoError(t, err)
	_, err = s.Send(mailboxContext(t, key, target), req)
	require.NoError(t, err)
	require.NoError(t, s.dispatchPending(context.Background()))
	require.Equal(t, 1, executed)
	pulled, err = s.Pull(readCtx, &mailboxpb.PullRequest{MailboxId: id})
	require.NoError(t, err)
	require.Len(t, pulled.Envelopes, 1)
	require.Equal(t, uint64(2), pulled.Envelopes[0].EventSeq)
	changed := proto.Clone(req).(*mailboxpb.SendRequest)
	changed.Envelope.Body, err = anypb.New(wrapperspb.String(
		"credit-twice",
	))
	require.NoError(t, err)
	_, err = s.Send(mailboxContext(t, key, target), changed)
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	_, err = s.Pull(mailboxContext(t, key, target), &mailboxpb.PullRequest{
		MailboxId: id,
	})
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestTransitionRollback checks that neither state nor egress becomes visible
// when a transaction fails before its durable commit.
func TestTransitionRollback(t *testing.T) {
	s := testServer(t, t.TempDir())
	want := errors.New("abort")
	err := s.transact(context.Background(), func() error {
		require.NoError(t, s.put("balance", 7))
		require.NoError(t, s.emit(
			"peer", "test", "Event", wrapperspb.Int64(7),
		))
		return want
	})
	require.ErrorIs(t, err, want)
	require.NotContains(t, s.state.Records, "balance")
	require.Empty(t, s.state.Mail)
}
