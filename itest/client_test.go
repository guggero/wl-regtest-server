//go:build wavewalletrpc && swapruntime

package itest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/rpc/swapclientrpc"
	"github.com/lightninglabs/wavelength/sdk/wavewalletdk"
	"github.com/lightninglabs/wavelength/waverpc"
	"github.com/stretchr/testify/require"
)

const (
	// integrationTimeout bounds one complete client scenario.
	integrationTimeout = 3 * time.Minute

	// pollInterval lets the client indexer and operator reconcile real
	// events.
	pollInterval = 500 * time.Millisecond

	// convergenceTimeout bounds a single asynchronous protocol transition.
	convergenceTimeout = time.Minute
)

// env selects explicit fixture endpoints without depending on a local checkout.
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// openWallet starts the pinned, unmodified upstream SDK against regtest.
func openWallet(t *testing.T, ctx context.Context) *wavewalletdk.Client {
	t.Helper()
	entropy := make([]byte, 16)
	_, err := rand.Read(entropy)
	require.NoError(t, err)
	wallet, _, err := wavewalletdk.StartExternalSeedWallet(
		ctx, wavewalletdk.Config{
			DataDir: t.TempDir(), Network: "regtest", DebugLevel: "info",
			ServerAddress: env(
				"WL_TEST_SERVER", "127.0.0.1:10010",
			), ServerInsecure: true,
			SwapServerAddress: env(
				"WL_TEST_SERVER", "127.0.0.1:10010",
			), SwapServerInsecure: true,
			WalletEsploraURL: env(
				"WL_TEST_ESPLORA", "http://127.0.0.1:3000",
			),
			WalletPollInterval: pollInterval, WalletRecoveryWindow: 10,
		}, wavewalletdk.ExternalSeedWalletRequest{SeedEntropy: entropy},
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, wallet.Stop()) })
	return wallet
}

// TestUpstreamClient validates real boarding, invoice onboarding into an empty
// wallet, OOR ownership and collaborative recovery using only public modules.
// The caller supplies a funded operator and a funded Bitcoin wallet RPC.
func TestUpstreamClient(t *testing.T) {
	if os.Getenv(
		"WL_INTEGRATION",
	) != "1" {

		t.Skip("set WL_INTEGRATION=1 with a funded regtest stack")
	}
	ctx, cancel := context.WithTimeout(t.Context(), integrationTimeout)
	defer cancel()
	bitcoin := &backend.Bitcoin{
		URL: env(
			"WL_TEST_BITCOIN_RPC",
			"http://127.0.0.1:18443",
		),
		User:     env("WL_TEST_BITCOIN_USER", "regtest"),
		Password: env("WL_TEST_BITCOIN_PASSWORD", "regtest"),
	}
	chain, err := bitcoin.Info(ctx)
	require.NoError(t, err)
	require.Equal(t, "regtest", chain.Chain)
	var miningAddress string
	require.NoError(t, bitcoin.Call(
		ctx, "getnewaddress", []any{}, &miningAddress,
	))
	mine := func() bool {
		return bitcoin.Call(ctx, "generatetoaddress", []any{
			1, miningAddress,
		}, nil) == nil
	}
	alice, bob := openWallet(t, ctx), openWallet(t, ctx)
	deposit, err := alice.Deposit(ctx, wavewalletdk.DepositRequest{
		AmountSatHint: 200000,
	})
	require.NoError(t, err)
	require.NoError(t, bitcoin.Call(
		ctx, "sendtoaddress", []any{
			deposit.Address, 0.002,
		}, nil,
	))
	require.Eventually(t, func() bool {
		if !mine() {
			return false
		}
		balance, err := alice.Balance(ctx)
		return err == nil && balance.ConfirmedSat == 200000
	}, convergenceTimeout, pollInterval)
	invoice, err := bob.SwapRPC().StartReceive(
		ctx, &swapclientrpc.StartReceiveRequest{
			AmountSat: 50000,
		},
	)
	require.NoError(t, err)
	_, err = alice.SwapRPC().StartPay(ctx, &swapclientrpc.StartPayRequest{
		Invoice: invoice.Invoice,
	})
	require.NoError(t, err)
	require.Eventually(t, func() bool {
		balance, err := bob.Balance(ctx)
		return err == nil && balance.ConfirmedSat == 50000
	}, convergenceTimeout, pollInterval)
	receive, err := bob.ArkRPC().NewReceiveScript(
		ctx, &waverpc.NewReceiveScriptRequest{
			IdempotencyKey: "upstream-receive",
		},
	)
	require.NoError(t, err)
	pub, err := hex.DecodeString(receive.PubkeyXonlyHex)
	require.NoError(t, err)
	sent, err := alice.ArkRPC().SendOOR(ctx, &waverpc.SendOORRequest{
		IdempotencyKey: "upstream-send", Recipients: []*waverpc.Output{{
			Destination: &waverpc.Output_Pubkey{
				Pubkey: pub,
			}, AmountSat: 20000,
		}},
	})
	require.NoError(t, err)
	require.NotEmpty(t, sent.SessionId)
	require.Eventually(t, func() bool {
		balance, err := bob.Balance(ctx)
		return err == nil && balance.ConfirmedSat == 70000
	}, convergenceTimeout, pollInterval)
	inventory, err := bob.List(ctx, wavewalletdk.ListRequest{
		View: wavewalletdk.ListViewVTXOs,
	})
	require.NoError(t, err)
	require.NotEmpty(t, inventory.VTXOs.VTXOs)
	coin := inventory.VTXOs.VTXOs[0]
	exited, err := bob.Exit(ctx, wavewalletdk.ExitRequest{
		Outpoint:    coin.Outpoint,
		Destination: miningAddress,
	})
	require.NoError(t, err)
	require.Equal(t, wavewalletdk.ExitPathCooperative, exited.Path)
	require.Eventually(t, func() bool {
		if !mine() {
			return false
		}
		var outputs []struct {
			Amount float64 `json:"amount"`
		}
		err := bitcoin.Call(ctx, "listunspent", []any{
			1, 9999999, []string{
				miningAddress,
			},
		}, &outputs)
		if err != nil {
			return false
		}
		for _, output := range outputs {
			if output.Amount == float64(coin.AmountSat)/1e8 {
				return true
			}
		}
		return false
	}, convergenceTimeout, pollInterval)
}
