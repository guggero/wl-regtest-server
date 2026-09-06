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
	DataDir         string
	Listen          string
	Bitcoin         *backend.Bitcoin
	LND             *backend.LND
	Clock           clock.Clock
	Log             *slog.Logger
	BoardingDelay   uint32
	ExitDelay       uint32
	BatchLifetime   uint32
	MinAmount       int64
	InventoryAmount int64
}

// DefaultConfig supplies block delays that leave room for swap recovery.
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
type Server struct {
	mailboxpb.UnimplementedMailboxServiceServer
	arkrpc.UnimplementedArkServiceServer
	swaprpc.UnimplementedSwapServiceServer
	lifecycle        sync.Mutex
	stopped          bool
	started          bool
	stopErr          error
	failures         chan error
	cfg              Config
	db               *store.Store
	mu               sync.Mutex
	state            snapshot
	router           *mailboxrpc.ServeMux
	key              *btcec.PrivateKey
	keySeed          [32]byte
	id               string
	wake             chan struct{}
	pending          []delivery
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

// New restores protocol state and binds the operator's persistent signing key.
func New(cfg Config) (*Server, error) {
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
	if s.state.Version != schemaVersion || len(s.state.Seed) != 32 {
		_ = db.Close()
		return nil, errors.New(
			"invalid or unsupported protocol snapshot",
		)
	}
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

// transact commits an in-memory transition and its messages atomically. No SQL
// transaction is held across handler IO. On persistence failure the transition
// is rolled back and no signed artifact or success response is released.
func (s *Server) transact(ctx context.Context, fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	before, err := json.Marshal(s.state)
	if err != nil {
		return err
	}
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
	close(s.wake)
	s.wake = make(chan struct{})
	return nil
}

// put records one JSON domain transcript inside the caller's transition.
func (s *Server) put(key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.state.Records[key] = raw
	return nil
}

// get decodes a record without treating absence as a populated zero value.
func get[T any](s *Server, key string) (*T, error) {
	raw, ok := s.state.Records[key]
	if !ok {
		return nil, nil
	}
	var value T
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, fmt.Errorf("decode record %s: %w", key, err)
	}
	return &value, nil
}

// Start verifies regtest backends before exposing the protocol listener.
func (s *Server) Start(ctx context.Context) error {
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.stopped || s.started {
		return errors.New("server has already been started or stopped")
	}
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
	s.lifecycle.Lock()
	defer s.lifecycle.Unlock()
	if s.stopped {
		return s.stopErr
	}
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
	var lastChainPoll time.Time
	for {
		select {
		case <-s.ctx.Done():
			return

		case <-s.cfg.Clock.TickAfter(workerInterval):
		}
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
