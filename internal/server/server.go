// Package server implements a durable, small-scale Wavelength regtest operator.
package server

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/guggero/wl-regtest-server/internal/store"
	"github.com/lightninglabs/wavelength/arkrpc"
	mailboxpb "github.com/lightninglabs/wavelength/mailbox/pb"
	mailboxrpc "github.com/lightninglabs/wavelength/mailbox/rpc"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/lightninglabs/wavelength/serverconn"
	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/lightningnetwork/lnd/clock"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/protobuf/proto"
)

const (
	// workerInterval bounds background delivery and confirmation polling.
	workerInterval = 100 * time.Millisecond

	// schemaVersion identifies the JSON protocol snapshot format.
	schemaVersion = 1
)

// Config configures the isolated regtest operator and its external backends.
type Config struct {
	// DataDir holds the private signing snapshot; Listen is the plaintext
	// gRPC bind address for the isolated test network.
	DataDir string
	Listen  string

	// Backends remain owned by the caller and must outlive the server.
	Bitcoin *backend.Bitcoin
	LND     *backend.LND
	Clock   clock.Clock
	Log     *slog.Logger

	// Delays are block counts for boarding refunds, unilateral VTXO exits,
	// and operator recovery of an untouched batch root, respectively.
	BoardingDelay uint32
	ExitDelay     uint32
	BatchLifetime uint32

	// Amounts are satoshis. InventoryAmount is the refill target, divided
	// among treasury leaves; MinAmount applies to each leaf.
	MinAmount       int64
	InventoryAmount int64
}

// DefaultConfig returns regtest policy defaults with heights and delays in
// blocks and amounts in satoshis. Callers must attach Bitcoin and LND backends
// before New; the returned clock and logger are ready to use.
func DefaultConfig() Config {
	return Config{
		DataDir: "data", Listen: "127.0.0.1:10010",
		Clock: clock.NewDefaultClock(), Log: slog.Default(),
		BoardingDelay: 144, ExitDelay: 10, BatchLifetime: 1440,
		MinAmount: 1000, InventoryAmount: 10_000_000,
	}
}

// snapshot stores byte encodings rather than runtime signing sessions. Records
// contain versioned domain transcripts; Mail and Requests form the durable
// edge.
type snapshot struct {
	Version  int
	Seed     []byte
	Records  map[string]json.RawMessage
	Mail     map[string]*mailbox
	Requests map[string]*request
}

// Server owns the protocol workers and serializes commits of their small state.
// Mailbox domain handlers run inside dispatchPending's transaction and must not
// enter transact again. Direct swap RPCs and background reconcilers open their
// own transactions. Helpers that inspect records require s.mu or exclusive
// offline access; backend connections remain owned by the caller.
type Server struct {
	mailboxpb.UnimplementedMailboxServiceServer
	arkrpc.UnimplementedArkServiceServer
	swaprpc.UnimplementedSwapServiceServer

	// lifecycle serializes Start and Stop, including worker registration.
	lifecycle sync.Mutex
	stopped   bool
	started   bool
	stopErr   error
	failures  chan error
	cfg       Config
	db        *store.Store

	// mu protects the snapshot, staged deliveries, wake channel and sampled
	// backend state. The router and signing identity are fixed by New.
	mu      sync.Mutex
	state   snapshot
	router  *mailboxrpc.ServeMux
	key     *btcec.PrivateKey
	keySeed [32]byte
	id      string
	wake    chan struct{}
	pending []delivery

	// Workers share this cancellation root and join before the store
	// closes. Each LND receiver is joined by its owning worker before
	// reconnecting.
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	grpc             *grpc.Server
	listener         net.Listener
	height           uint32
	blockHash        string
	lndPubkey        []byte
	interceptorReady bool
}

// New opens the state database, restores signing identity and registers the
// mailbox handlers without starting workers or making backend requests. The
// caller must call Stop even if Start later fails. Config delays are block
// counts and amount limits are satoshis; invalid dependencies or policy limits
// fail before a listener is created.
func New(cfg Config) (*Server, error) {
	// Reject missing dependencies and unusable policy bounds before opening
	// persistent state. In particular, every initial inventory leaf must
	// clear the minimum output amount.
	if cfg.Bitcoin == nil || cfg.LND == nil || cfg.Clock == nil {
		return nil, errors.New("Bitcoin, LND and clock are required")
	}
	if cfg.ExitDelay == 0 || cfg.BatchLifetime <= cfg.BoardingDelay ||
		cfg.MinAmount < 330 ||
		cfg.InventoryAmount < inventoryLeaves*cfg.MinAmount {

		return nil, errors.New("invalid regtest policy limits")
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}

	// Restore the complete snapshot as a unit. Records, request
	// deduplication and queued mail must describe the same last-committed
	// transition.
	db, err := store.Open(filepath.Join(cfg.DataDir, "server.sqlite"))
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, db: db, router: mailboxrpc.NewServeMux(),
		wake: make(chan struct{}), failures: make(chan error, 1)}
	raw, err := db.Load(context.Background())
	if err == nil && len(raw) > 0 {
		err = json.Unmarshal(raw, &s.state)
	}
	if err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("load protocol state: %w", err)
	}

	// Only an empty database gets a new seed. Generating one while
	// restoring existing records would orphan their previously signed
	// spending paths.
	if len(raw) == 0 {
		s.state = snapshot{Version: schemaVersion, Seed: make(
			[]byte, 32,
		),
			Records:  make(map[string]json.RawMessage),
			Mail:     make(map[string]*mailbox),
			Requests: make(map[string]*request)}
		if _, err := rand.Read(s.state.Seed); err != nil {
			_ = db.Close()
			return nil, err
		}
	}

	// Check the envelope before interpreting seed material. A structurally
	// decodable snapshot can still belong to an incompatible state format.
	if s.state.Version != schemaVersion || len(s.state.Seed) != 32 {
		_ = db.Close()
		return nil, errors.New(
			"invalid or unsupported protocol snapshot",
		)
	}

	// Derive the advertised identity from the persisted seed and bind
	// handlers to this same server instance. Mailbox Ark calls already hold
	// the state lock.
	s.keySeed = [32]byte(s.state.Seed)
	s.key = s.deriveKey("operator")
	s.id = serverconn.PubKeyMailboxID(s.key.PubKey())
	roundpb.RegisterRoundServiceMailboxServer(s.router, s)
	arkrpc.RegisterIndexerServiceMailboxServer(s.router, s)
	arkrpc.RegisterArkServiceMailboxServer(s.router, mailboxArk{s})
	s.registerOOR()

	// Commit the identity even when no protocol operation has arrived yet.
	// A no-op transition intentionally skips writes, so cannot initialize
	// it.
	if len(raw) == 0 {
		encoded, err := json.Marshal(s.state)
		if err == nil {
			err = db.Save(context.Background(), encoded)
		}
		if err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("persist operator identity: %w", err)
		}
	}
	return s, nil
}

// deriveKey derives independent server-owned participant and operator keys.
// Domain strings are persisted with their operations before keys are exposed.
func (s *Server) deriveKey(domain string) *btcec.PrivateKey {
	// The original domain is part of the persisted key derivation format.
	// Retain it across project renames so existing seeds keep their keys.
	h := hmac.New(sha256.New, s.keySeed[:])
	_, _ = h.Write([]byte("lw-regtest-server/v1/" + domain))
	key, _ := btcec.PrivKeyFromBytes(h.Sum(nil))
	return key
}

// transact serializes one in-memory state transition and saves its records,
// request outcomes and queued mail in one snapshot. fn runs with s.mu held and
// must not enter transact recursively. Backend IO may occur inside fn, but no
// SQLite transaction is open during it. A failed transition restores the prior
// state; successful readers are notified only after the snapshot is durable.
func (s *Server) transact(ctx context.Context, fn func() error) error {
	// Retain a serialized rollback image before invoking protocol code.
	// This also isolates callers from mutations made by a failed signing or
	// RPC step.
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := json.Marshal(s.state)
	if err != nil {
		return err
	}

	// Handlers stage deliveries instead of waking readers themselves. Fold
	// the outbox into the same snapshot as the state that justifies each
	// response.
	s.pending = nil
	err = fn()
	if err == nil {
		for _, event := range s.pending {
			if err = s.enqueue(
				event.recipient, event.envelope,
			); err != nil {

				break
			}
		}
	}
	s.pending = nil

	// Avoid rewriting unchanged snapshots. Once state has changed, finish
	// the bounded durability write even if the original RPC caller has
	// disconnected; its retry must recover the committed result rather than
	// repeat side effects.
	if err == nil {
		var after []byte
		after, err = json.Marshal(s.state)
		if err == nil && bytes.Equal(before, after) {
			return nil
		}
		if err == nil {
			commitCtx, cancel := context.WithTimeout(
				context.WithoutCancel(ctx), backend.RPCTimeout,
			)
			err = s.db.Save(commitCtx, after)
			cancel()
		}
	}

	// Discard both domain mutations and queued mail on failure. No reader
	// has been notified, so a retry starts from the last acknowledged
	// snapshot.
	if err != nil {
		// before was produced from this exact type immediately above.
		var restored snapshot
		if restoreErr := json.Unmarshal(
			before, &restored,
		); restoreErr != nil {

			return fmt.Errorf("restore snapshot after %w: %v", err, restoreErr)
		}
		s.state = restored
		return err
	}

	// Replacing the notification channel wakes every current mailbox waiter
	// while giving the next generation a fresh channel to wait on.
	close(s.wake)
	s.wake = make(chan struct{})
	return nil
}

// put encodes one domain record into the in-memory snapshot. The caller must
// hold s.mu or have exclusive offline access; this helper does not save the
// database or notify readers on its own. Serialization failure leaves this
// record unchanged.
func (s *Server) put(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.state.Records[key] = raw
	return nil
}

// get decodes a domain record into a detached value while the caller holds s.mu
// or has exclusive offline access. Missing keys return nil, nil so callers can
// distinguish absence from a stored zero value. Mutating the result requires
// put to update the snapshot; malformed stored JSON is returned as an error.
func get[T any](s *Server, key string) (*T, error) {
	raw, ok := s.state.Records[key]
	if !ok {
		return nil, nil
	}

	// Decode a fresh value so a caller cannot accidentally mutate the
	// stored JSON through a returned pointer without explicitly recording
	// the update.
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode record %s: %w", key, err)
	}
	return &value, nil
}

// Start verifies that Core and LND are synchronized to the same regtest chain,
// then binds the listener and launches owned workers. Its context controls
// their lifetime; call Stop to join them and close persistence. A started or
// stopped instance cannot be started again. Readiness does not promise funded
// inventory or an available Lightning route for a later operation.
func (s *Server) Start(ctx context.Context) error {
	// Serialize lifecycle changes so Stop cannot close resources while
	// Start is still adding workers to the shutdown wait group.
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.stopped || s.started {
		return errors.New("server has already been started or stopped")
	}

	// Probe both backends under one bounded startup deadline. A network
	// mismatch or unsynchronized Lightning wallet must fail before clients
	// can submit funds.
	readyCtx, cancel := context.WithTimeout(ctx, backend.RPCTimeout)
	defer cancel()
	info, err := s.cfg.Bitcoin.Info(readyCtx)
	if err != nil {
		return err
	}
	if info.Chain != "regtest" {
		return errors.New("Bitcoin Core must run on regtest")
	}
	lndInfo, err := s.cfg.LND.Info(readyCtx)
	if err != nil {
		return err
	}
	if !lndInfo.SyncedToChain {
		return errors.New("LND is not synchronized to its chain")
	}

	// Matching the network name alone does not distinguish independent
	// regtest chains. Compare the canonical block at LND's reported height.
	var lndBlock string
	if err := s.cfg.Bitcoin.Call(
		readyCtx, "getblockhash", []any{lndInfo.BlockHeight}, &lndBlock,
	); err != nil {

		return fmt.Errorf("verify LND chain: %w", err)
	}
	if lndBlock != lndInfo.BlockHash {
		return errors.New(
			"Bitcoin Core and LND disagree on the regtest chain",
		)
	}

	// Seed protocol terms from verified backend state, then expose the
	// handlers. Health covers the RPC process; spendability is checked per
	// operation.
	s.height, s.blockHash = info.Blocks, info.BestBlockHash
	s.lndPubkey, err = hex.DecodeString(lndInfo.IdentityPubkey)
	if err != nil {
		return err
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.grpc = grpc.NewServer()
	mailboxpb.RegisterMailboxServiceServer(s.grpc, s)
	arkrpc.RegisterArkServiceServer(s.grpc, s)
	swaprpc.RegisterSwapServiceServer(s.grpc, s)
	healthServer := health.NewServer()
	healthServer.SetServingStatus(
		"", grpc_health_v1.HealthCheckResponse_SERVING,
	)
	grpc_health_v1.RegisterHealthServer(s.grpc, healthServer)
	s.listener, err = net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		s.cancel()
		return err
	}

	// Register every worker before releasing the lifecycle lock. The
	// listener reports unexpected failure to the process owner and cancels
	// sibling workers.
	s.started = true
	s.wg.Add(4)
	go func() {
		defer s.wg.Done()
		if err := s.grpc.Serve(s.listener); err != nil &&
			!errors.Is(err, grpc.ErrServerStopped) {

			s.failures <- fmt.Errorf("RPC listener failed: %w", err)
			s.cancel()
		}
	}()
	go s.run()
	go s.runSwaps()
	go s.runInterceptor()
	return nil
}

// Address returns the actual bound address, allowing ephemeral test listeners.
func (s *Server) Address() string {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// Failures reports an unexpected listener failure to the process owner.
func (s *Server) Failures() <-chan error {
	return s.failures
}

// Stop cancels workers and RPCs before closing persistence. Repeated calls
// return the original close result; a stopped instance cannot be restarted.
func (s *Server) Stop() error {
	// Make shutdown idempotent and exclude a concurrent Start. Every caller
	// observes the same stored database-close result.
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.stopped {
		return s.stopErr
	}

	// Cancel RPCs and background work before closing the database. Joining
	// all workers prevents a late transition from writing through a closed
	// connection.
	s.stopped = true
	if s.cancel != nil {
		s.cancel()
	}
	if s.grpc != nil {
		s.grpc.Stop()
	}
	s.wg.Wait()
	s.stopErr = s.db.Close()
	return s.stopErr
}

// run drives durable requests and resamples the authoritative chain height.
func (s *Server) run() {
	defer s.wg.Done()

	// Mailbox work and inventory progress need short polling latency,
	// whereas recovery scans and expiry checks are throttled to avoid
	// repeated chain scans.
	var lastChainPoll time.Time
	for {
		select {
		// Cancellation exits before beginning another round of backend
		// work.
		case <-s.ctx.Done():
			return

		// Use the configured clock so tests control when another poll
		// is due.
		case <-s.cfg.Clock.TickAfter(workerInterval):
		}

		// Replay committed mailbox requests first, then refresh the
		// shared tip used by admission and timeout checks. A failed tip
		// read retains the last sample.
		if err := s.dispatchPending(s.ctx); err != nil {
			s.cfg.Log.Error(
				"commit mailbox transition", "error", err,
			)
		}
		info, err := s.cfg.Bitcoin.Info(s.ctx)
		if err == nil {
			s.mu.Lock()
			s.height, s.blockHash = info.Blocks, info.BestBlockHash
			s.mu.Unlock()
		}

		// Recover spent or expired backing outputs before allocating
		// more liquidity. Individual failures remain retryable and must
		// not stop unrelated pollers.
		if s.cfg.Clock.Now().Sub(lastChainPoll) >= time.Second {
			if err := s.expireAwaitingSwaps(s.ctx); err != nil {
				s.cfg.Log.Debug(
					"swap expiry pending", "error", err,
				)
			}
			if err := s.expireQuotes(s.ctx); err != nil {
				s.cfg.Log.Debug(
					"quote expiry pending", "error", err,
				)
			}
			if err := s.pollVTXOChain(s.ctx); err != nil {
				s.cfg.Log.Debug(
					"chain reconciliation pending", "error",
					err,
				)
			}
			if err := s.pollSwapChain(s.ctx); err != nil {
				s.cfg.Log.Debug(
					"on-chain swap recovery pending",
					"error", err,
				)
			}
			if err := s.sweepExpiredRoots(s.ctx); err != nil {
				s.cfg.Log.Debug(
					"expired root recovery pending",
					"error", err,
				)
			}
			lastChainPoll = s.cfg.Clock.Now()
		}

		// Reconcile credit funding before replenishing inventory, then
		// drive saved rounds toward publication and confirmation. Each
		// poller retains its own retry state when a backend is
		// unavailable.
		if err := s.pollCredits(s.ctx); err != nil {
			s.cfg.Log.Debug(
				"credit reconciliation pending", "error", err,
			)
		}
		if err := s.ensureInventory(s.ctx); err != nil {
			s.cfg.Log.Debug(
				"inventory funding pending", "error", err,
			)
		}
		if err := s.pollRounds(s.ctx); err != nil {
			s.cfg.Log.Debug(
				"round publication pending", "error", err,
			)
		}
	}
}

// marshal encodes a protocol message for durable storage.
func marshal(msg proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(msg)
}
