package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/google/uuid"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/lib/tx/psbtutil"
	mailboxpb "github.com/lightninglabs/wavelength/mailbox/pb"
	mailboxrpc "github.com/lightninglabs/wavelength/mailbox/rpc"
	"github.com/lightninglabs/wavelength/rpc/oorpb"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/lightninglabs/wavelength/serverconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// maxMailboxBatch bounds each pull and each durable dispatcher turn.
	maxMailboxBatch = 100

	// maxEnvelopeSize bounds persisted, user-controlled request bodies.
	maxEnvelopeSize = 4 << 20

	// maxPullWait bounds idle requests without delaying daemon shutdown.
	maxPullWait = 5 * time.Second
)

// mailbox retains monotonically sequenced envelopes until durably acknowledged.
type mailbox struct {
	Next     uint64
	Ack      uint64
	Messages map[uint64][]byte
}

// request preserves one ingress intent and its response beyond mailbox pruning.
type request struct {
	Envelope []byte
	Digest   []byte
	Response []byte
	Done     bool
	Order    uint64
}

// delivery is held until the enclosing state transition commits.
type delivery struct {
	recipient string
	envelope  *mailboxpb.Envelope
}

// principalKey is private to prevent handlers confusing authenticated identity
// with fields supplied inside an RPC body.
type principalKey struct{}

// principal returns the authenticated sender for a mailbox-dispatched request.
func principal(ctx context.Context) string {
	id, _ := ctx.Value(principalKey{}).(string)
	return id
}

// mailboxPubkey decodes the owner component of a plain or per-swap mailbox ID.
func mailboxPubkey(id string) (*btcec.PublicKey, error) {
	owner, _, _ := strings.Cut(id, ":")
	raw, err := hex.DecodeString(owner)
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument, "invalid mailbox ID",
		)
	}
	key, err := btcec.ParsePubKey(raw)
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument, "invalid mailbox key",
		)
	}
	return key, nil
}

// authenticate validates the exact mailbox authorization carried by the client.
func authenticate(ctx context.Context, owner, recipient string,
	headers map[string]string) error {

	key, err := mailboxPubkey(owner)
	if err != nil {
		return err
	}

	// Accept transport metadata or the envelope header used by mailbox
	// clients, but verify the signature against the exact addressed
	// mailbox.
	md, _ := metadata.FromIncomingContext(ctx)
	sig := ""
	if values := md.Get(serverconn.AuthHeaderKey); len(values) == 1 {
		sig = values[0]
	}
	if sig == "" {
		sig = headers[serverconn.AuthHeaderKey]
	}
	if err := serverconn.VerifyMailboxAuth(
		key, recipient, sig,
	); err != nil {

		return status.Error(
			codes.Unauthenticated, "invalid mailbox authorization",
		)
	}
	return nil
}

// Send durably admits one authenticated request without executing it inline.
// Success acknowledges durable admission, not domain completion. Mutation
// retries must preserve the body and routing under their sender-scoped key;
// conflicts return AlreadyExists. Heartbeats bypass durable admission.
func (s *Server) Send(ctx context.Context,
	req *mailboxpb.SendRequest) (*mailboxpb.SendResponse, error) {

	// Reject unsupported envelopes and versions before admission; the
	// durable dispatcher assumes a typed request or protocol event.
	e := req.GetEnvelope()
	if e == nil || e.Rpc == nil || (e.Rpc.Kind != mailboxpb.RpcMeta_KIND_REQUEST &&
		e.Rpc.Kind != mailboxpb.RpcMeta_KIND_EVENT) {

		return nil, status.Error(
			codes.InvalidArgument, "incomplete RPC envelope",
		)
	}
	if e.ProtocolVersion != 1 || e.ArkProtocolVersion != 1 {
		return &mailboxpb.SendResponse{Status: &mailboxpb.Status{
			Code: "ARK_VERSION_MISMATCH", Message: "unsupported " +
				"protocol version",
			ServerProtocolVersion: 1, MinSupportedProtocolVersion: 1,
			SupportedMailboxVersions: []uint32{
				1,
			}, SupportedArkVersions: []uint32{
				1,
			},
		}}, nil
	}

	// Bind routing and reply identity to the authenticated sender so an
	// envelope cannot redirect a response or impersonate another
	// participant.
	if e.Recipient != serverconn.CompoundMailboxID(s.id, e.Sender) ||
		e.Rpc.ReplyTo != e.Sender {

		return nil, status.Error(
			codes.PermissionDenied, "invalid RPC addressing",
		)
	}
	if err := authenticate(
		ctx, e.Sender, e.Recipient, e.Headers,
	); err != nil {

		return nil, err
	}

	// Authenticated heartbeats only keep the connection active; they carry
	// no durable domain operation and do not need a request ledger entry.
	if e.Rpc.Service == serverconn.HeartbeatService &&
		e.Rpc.Method == serverconn.HeartbeatMethod &&
		e.Rpc.Kind == mailboxpb.RpcMeta_KIND_EVENT {

		return &mailboxpb.SendResponse{
			Status: &mailboxpb.Status{
				Ok: true,
			},
		}, nil
	}

	// Economic requests need stable retry identity and bounded serialized
	// contents before consuming durable storage.
	if e.Body == nil || e.IdempotencyKey == "" || (e.Rpc.Kind == mailboxpb.RpcMeta_KIND_REQUEST &&
		e.Rpc.CorrelationId == "") {

		return nil, status.Error(
			codes.InvalidArgument, "incomplete RPC body",
		)
	}
	raw, err := marshal(e)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxEnvelopeSize {
		return nil, status.Error(
			codes.ResourceExhausted, "envelope too large",
		)
	}

	// Correlation can vary on a retry; the semantic body and routing
	// cannot.
	message, err := e.Body.UnmarshalNew()
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument, "invalid typed RPC body",
		)
	}
	canonical, err := marshal(message)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(
		append([]byte(fmt.Sprintf("%d\x00%s\x00%s\x00%s\x00", e.Rpc.Kind, e.Rpc.Service, e.Rpc.Method, e.Body.TypeUrl)), canonical...),
	)
	key := e.Sender + "/" + e.IdempotencyKey

	// Read queries re-sign their scope proofs on durable retries. Their
	// logical query key can be reused with a fresh nonce or expiry, so
	// cache only an exact signed query, independently of mutating intents.
	if readOnlyMailbox(e.Rpc.Service, e.Rpc.Method) {
		key += "/" + hex.EncodeToString(digest[:])
	}

	// Persist ingress before acknowledging it. Completed retries replay a
	// cached response with the caller's current correlation ID; pending
	// ones remain queued exactly once.
	err = s.transact(ctx, func() error {
		old := s.state.Requests[key]
		if old != nil {
			if !bytes.Equal(old.Digest, digest[:]) {
				return status.Error(
					codes.AlreadyExists,
					"idempotency key conflict",
				)
			}
			if old.Done && len(old.Response) > 0 {
				var response mailboxpb.Envelope
				if err := proto.Unmarshal(
					old.Response, &response,
				); err != nil {

					return err
				}
				response.Rpc.CorrelationId = e.Rpc.CorrelationId
				response.MsgId = uuid.NewString()
				return s.enqueue(e.Sender, &response)
			}
			return nil
		}
		s.state.Requests[key] = &request{
			Envelope: raw, Digest: digest[:], Order: uint64(len(
				s.state.Requests,
			)),
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.wakeDispatcher()
	return &mailboxpb.SendResponse{Status: &mailboxpb.Status{Ok: true}}, nil
}

// wakeDispatcher asks the worker to dispatch persisted requests without
// waiting for its next tick. It never blocks: a signal already pending
// covers this request too.
func (s *Server) wakeDispatcher() {
	select {
	case s.dispatchWake <- struct{}{}:
	default:
	}
}

// readOnlyMailbox identifies methods whose retries cannot duplicate an
// economic operation and may carry freshly generated authorization proofs.
func readOnlyMailbox(service, method string) bool {
	switch service {
	case "arkrpc.ArkService":
		return method == "GetInfo" || method == "EstimateFee"

	case "arkrpc.IndexerService":
		switch method {
		case "ListMyReceiveScripts", "ListVTXOsByScripts", "GetSubtre" +
			"eByScripts",
			"ListVTXOEventsByScripts", "ListOORRecipientEventsByS" +
				"cript", "GetOORSessionByTxid":
			return true
		}
	}
	return false
}

// enqueue assigns one monotonic sequence inside a state transition.
// The caller must be inside transact. e is mutated to carry its assigned
// sequence, and serialization or persistence failure must abort the transition.
func (s *Server) enqueue(recipient string, e *mailboxpb.Envelope) error {
	// Sequence allocation and envelope insertion share the state
	// transaction so acknowledgement cursors never refer to an uncommitted
	// message.
	box := s.state.Mail[recipient]
	if box == nil {
		box = &mailbox{Next: 1, Messages: make(map[uint64][]byte)}
		s.state.Mail[recipient] = box
	}
	e.EventSeq = box.Next
	box.Next++
	raw, err := marshal(e)
	if err != nil {
		return err
	}
	box.Messages[e.EventSeq] = raw
	return nil
}

// emit schedules a typed push after the immediate RPC acknowledgement.
// The caller must be inside transact; returning successfully stages the event
// but does not make it visible until the enclosing snapshot has been saved.
func (s *Server) emit(recipient, service, method string,
	msg proto.Message) error {

	// Stage protocol events separately from the direct RPC response. The
	// transaction flushes these only after the response has been enqueued.
	body, err := anypb.New(msg)
	if err != nil {
		return err
	}
	e := &mailboxpb.Envelope{
		ProtocolVersion: 1, ArkProtocolVersion: 1,
		MsgId: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		Sender: s.id, Recipient: recipient,
		CreatedAtUnixMs: s.cfg.Clock.Now().UnixMilli(),
		Body:            body, Rpc: &mailboxpb.RpcMeta{
			Kind: mailboxpb.RpcMeta_KIND_EVENT, Service: service, Method: method,
		},
	}
	s.pending = append(s.pending, delivery{
		recipient: recipient,
		envelope:  e,
	})
	return nil
}

// Pull returns unacknowledged events with bounded, wakeable long polling.
// Cursor is the first sequence to include; NextCursor follows the last
// returned envelope and can be passed to AckUpTo. MaxEnvelopes defaults to 100
// and is capped there; WaitTimeoutMs is capped at five seconds.
func (s *Server) Pull(ctx context.Context,
	req *mailboxpb.PullRequest) (*mailboxpb.PullResponse, error) {

	// Mailbox contents are private to their key owner, including during
	// long polling; authenticate before looking at cursors or pending
	// events.
	if err := authenticate(
		ctx, req.MailboxId, req.MailboxId, nil,
	); err != nil {

		return nil, err
	}

	// Cap both wait time and page size so idle or backlogged clients cannot
	// hold a request indefinitely or receive an unbounded response.
	wait := min(
		time.Duration(req.WaitTimeoutMs)*time.Millisecond, maxPullWait,
	)
	timer := s.cfg.Clock.TickAfter(wait)
	limit := int(req.MaxEnvelopes)
	if limit == 0 || limit > maxMailboxBatch {
		limit = maxMailboxBatch
	}

	// Read the current message set and wake channel under the same lock.
	// A commit between lookup and waiting then closes the captured channel
	// and cannot leave this pull asleep despite available messages.
	for {
		s.mu.Lock()
		response := &mailboxpb.PullResponse{Status: &mailboxpb.Status{
			Ok: true,
		},
			NextCursor: req.Cursor}
		box := s.state.Mail[req.MailboxId]
		if box != nil {
			for seq := max(req.Cursor, box.Ack, uint64(
				1,
			)); seq < box.Next &&
				len(response.Envelopes) < limit; seq++ {

				if raw, ok := box.Messages[seq]; ok {
					var envelope mailboxpb.Envelope
					if err := proto.Unmarshal(
						raw, &envelope,
					); err != nil {

						s.mu.Unlock()
						return nil, err
					}
					response.Envelopes = append(
						response.Envelopes, &envelope,
					)
					response.NextCursor = seq + 1
				}
			}
		}
		wake := s.wake
		s.mu.Unlock()
		if len(response.Envelopes) > 0 || wait == 0 {
			s.cfg.Log.Debug(
				"mailbox delivered", "mailbox", req.MailboxId,
				"cursor", req.Cursor, "next",
				response.NextCursor, "count",
				len(response.Envelopes),
			)
			return response, nil
		}

		// Cancellation terminates the RPC, timeout returns an empty
		// page, and a committed-state wake triggers another lookup
		// without resetting the deadline.
		select {
		case <-ctx.Done():
			return nil, status.FromContextError(ctx.Err()).Err()

		case <-timer:
			return response, nil

		case <-wake:
		}
	}
}

// AckUpTo persists an exclusive acknowledgement watermark without allowing a
// caller to discard future, undelivered events.
// All envelopes with sequence less than Cursor are pruned atomically. A
// cursor beyond the next assigned sequence is invalid; repeated or older
// acknowledgements are harmless.
func (s *Server) AckUpTo(ctx context.Context,
	req *mailboxpb.AckUpToRequest) (*mailboxpb.AckUpToResponse, error) {

	if err := authenticate(
		ctx, req.MailboxId, req.MailboxId, nil,
	); err != nil {

		return nil, err
	}

	// The cursor is exclusive and monotonic. Validate it before pruning so
	// a typo cannot discard messages that have not even been assigned yet.
	err := s.transact(ctx, func() error {
		box := s.state.Mail[req.MailboxId]
		if box == nil {
			if req.Cursor > 1 {
				return status.Error(
					codes.InvalidArgument,
					"cursor beyond mailbox",
				)
			}
			return nil
		}
		if req.Cursor > box.Next {
			return status.Error(
				codes.InvalidArgument, "cursor beyond mailbox",
			)
		}
		box.Ack = max(box.Ack, req.Cursor)
		for seq := range box.Messages {
			if seq < box.Ack {
				delete(box.Messages, seq)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return &mailboxpb.AckUpToResponse{
		Status: &mailboxpb.Status{
			Ok: true,
		},
	}, nil
}

// dispatchPending executes admitted requests in arrival order. Domain handlers
// run inside the same state transition as their response and pushed events.
func (s *Server) dispatchPending(ctx context.Context) error {
	// Recover admitted requests in ingress order rather than map order,
	// bounding each pass so chain and settlement workers also make
	// progress.
	s.mu.Lock()
	keys := make([]string, 0)
	for key, req := range s.state.Requests {
		if !req.Done {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		return s.state.Requests[keys[i]].Order < s.state.Requests[keys[j]].Order
	})
	s.mu.Unlock()

	// Commit each handler's domain changes together with completion and its
	// response; a crash cannot leave a successful operation eligible to run
	// again.
	for _, key := range keys[:min(len(keys), maxMailboxBatch)] {
		err := s.transact(ctx, func() error {
			req := s.state.Requests[key]
			var e mailboxpb.Envelope
			if err := proto.Unmarshal(
				req.Envelope, &e,
			); err != nil {

				return err
			}

			// Handler failures roll back domain writes but retain
			// ingress and a correlated error response, so clients
			// never wait indefinitely.
			before, err := json.Marshal(s.state.Records)
			if err != nil {
				return err
			}
			callCtx, callCancel := context.WithTimeout(
				context.WithValue(ctx, principalKey{}, e.Sender),
				backend.RPCTimeout,
			)
			defer callCancel()
			result, callErr := s.router.ServeRPC(
				callCtx, e.Rpc.Service, e.Rpc.Method,
				e.Body.Value,
			)
			if callErr != nil {
				s.pending = nil
				s.state.Records = nil
				if err := json.Unmarshal(
					before, &s.state.Records,
				); err != nil {

					return err
				}
				if errors.Is(callErr, mailboxrpc.ErrNoHandler) {
					callErr = status.Error(
						codes.Unimplemented,
						callErr.Error(),
					)
				}
				s.cfg.Log.Debug(
					"mailbox request rejected", "method",
					e.Rpc.Method, "error", callErr,
				)
			}

			// One-way protocol events have no RPC response.
			// Translate failures into the domain events that the
			// OOR and round client actors wait for.
			if e.Rpc.Kind == mailboxpb.RpcMeta_KIND_EVENT {
				req.Done = true
				if callErr != nil && e.Rpc.Service == oorpb.ServiceName && e.Rpc.Method == oorpb.MethodSubmitPackage {
					var submitted oorpb.SubmitPackageRequest
					if err := proto.Unmarshal(
						e.Body.Value, &submitted,
					); err == nil {

						packet, err := psbtutil.Parse(
							submitted.ArkPsbt,
						)
						if err == nil {
							rejection := oorpb.NewSubmitPackageRejection(
								packet.UnsignedTx.TxHash(),
								oorpb.OORRejectCode_OOR_REJECT_UNSPECIFIED, callErr.Error(),
								s.height,
							)
							return s.emit(
								e.Sender,
								oorpb.ServiceName,
								oorpb.MethodSubmitPackage,
								rejection,
							)
						}
					}
				}
				if callErr != nil &&
					e.Rpc.Service == roundpb.ServiceName {

					return s.emit(
						e.Sender, roundpb.ServiceName,
						roundpb.MethodError,
						&roundpb.ClientErrorResp{
							ErrorMsg: callErr.Error(),
						},
					)
				}
				return nil
			}

			// For ordinary RPCs, retain the correlated success or
			// error even after mailbox pruning, allowing a semantic
			// retry to recover its original outcome.
			var body *anypb.Any
			if result != nil && callErr == nil {
				body, err = anypb.New(result)
				if err != nil {
					return err
				}
			}
			response := &mailboxpb.Envelope{
				ProtocolVersion: 1, ArkProtocolVersion: 1,
				MsgId: uuid.NewString(), IdempotencyKey: e.IdempotencyKey,
				Sender: s.id, Recipient: e.Sender, Body: body,
				Headers: mailboxrpc.EncodeErrorHeaders(callErr),
				Rpc: &mailboxpb.RpcMeta{Kind: mailboxpb.RpcMeta_KIND_RESPONSE,
					Service: e.Rpc.Service, Method: e.Rpc.Method,
					CorrelationId: e.Rpc.CorrelationId},
			}
			req.Response, err = marshal(response)
			if err != nil {
				return err
			}
			req.Done = true
			return s.enqueue(e.Sender, response)
		})
		if err != nil {
			return fmt.Errorf("dispatch %s: %w", key, err)
		}
	}
	return nil
}
