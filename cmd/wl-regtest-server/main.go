// Command wl-regtest-server runs a local Wavelength protocol operator.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/guggero/wl-regtest-server/internal/server"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// env returns an environment override or the documented default.
func env(name, fallback string) string {
	if value, ok := os.LookupEnv(name); ok {
		return value
	}
	return fallback
}

// main reports startup failures with a nonzero process exit status.
func main() {
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

// run owns connections, signal cancellation, and ordered daemon shutdown.
func run() error {
	cfg := server.DefaultConfig()
	bitcoin := &backend.Bitcoin{}
	lndCfg := backend.LNDConfig{}
	flags := flag.NewFlagSet("wl-regtest-server", flag.ContinueOnError)
	flags.StringVar(
		&cfg.Listen, "listen", env("WL_LISTEN", "0.0.0.0:10010"),
		"gRPC listener (regtest plaintext)",
	)
	flags.StringVar(
		&cfg.DataDir, "datadir", env("WL_DATA_DIR", "data"),
		"persistent server directory",
	)
	flags.StringVar(
		&bitcoin.URL, "bitcoin-rpc",
		env("BITCOIN_RPC_URL", "http://127.0.0.1:18443"),
		"Bitcoin Core JSON-RPC URL",
	)
	flags.StringVar(
		&bitcoin.User, "bitcoin-user",
		env("BITCOIN_RPC_USER", "regtest"), "Bitcoin Core RPC user",
	)
	flags.StringVar(
		&bitcoin.Password, "bitcoin-password",
		env("BITCOIN_RPC_PASSWORD", ""), "Bitcoin Core RPC password",
	)
	flags.StringVar(
		&lndCfg.Address, "lnd-rpc",
		env("LND_RPC_ADDRESS", "127.0.0.1:10009"), "LND gRPC address",
	)
	flags.StringVar(
		&lndCfg.TLSCert, "lnd-tls-cert", env("LND_TLS_CERT", ""),
		"LND TLS certificate path",
	)
	flags.StringVar(
		&lndCfg.Macaroon, "lnd-macaroon", env("LND_MACAROON", ""),
		"LND admin macaroon path",
	)
	debug := flags.Bool("debug", false, "enable protocol debug logging")
	health := flags.Bool("healthcheck", false, "query gRPC health and exit")
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *health {
		return checkHealth(cfg.Listen)
	}
	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	cfg.Log = slog.New(slog.NewTextHandler(
		os.Stderr, &slog.HandlerOptions{
			Level: level,
		},
	))
	ctx, cancel := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer cancel()
	lnd, err := backend.Connect(lndCfg)
	if err != nil {
		return err
	}
	defer func() { _ = lnd.Conn.Close() }()
	cfg.Bitcoin, cfg.LND = bitcoin, lnd
	daemon, err := server.New(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = daemon.Stop() }()
	if err := daemon.Start(ctx); err != nil {
		return err
	}
	cfg.Log.Info(
		"Wavelength regtest operator listening", "address",
		daemon.Address(),
	)
	select {
	case <-ctx.Done():
		return nil

	case err := <-daemon.Failures():
		return err
	}
}

// checkHealth implements the container's bounded readiness probe.
func checkHealth(address string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(
		insecure.NewCredentials(),
	))
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	response, err := grpc_health_v1.NewHealthClient(conn).Check(
		ctx, &grpc_health_v1.HealthCheckRequest{},
	)
	if err != nil {
		return err
	}
	if response.Status != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("server health: %s", response.Status)
	}
	return nil
}
