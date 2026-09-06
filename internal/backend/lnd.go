package backend

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/lightningnetwork/lnd/lnrpc/invoicesrpc"
	"github.com/lightningnetwork/lnd/lnrpc/routerrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// LNDConfig identifies a funded regtest node and its credentials.
type LNDConfig struct {
	Address  string
	TLSCert  string
	Macaroon string
	Insecure bool
}

// macaroonCredential attaches the configured LND capability token.
type macaroonCredential struct {
	hex    string
	secure bool
}

// GetRequestMetadata implements gRPC's per-request credential interface.
func (m macaroonCredential) GetRequestMetadata(context.Context,
	...string) (map[string]string, error) {

	return map[string]string{"macaroon": m.hex}, nil
}

// RequireTransportSecurity prevents credentials crossing plaintext by default.
func (m macaroonCredential) RequireTransportSecurity() bool {
	return m.secure
}

// LND owns clients for wallet funding and real Lightning settlement.
type LND struct {
	Conn      *grpc.ClientConn
	Lightning lnrpc.LightningClient
	Wallet    walletrpc.WalletKitClient
	Router    routerrpc.RouterClient
	Invoices  invoicesrpc.InvoicesClient
}

// Connect opens the LND connection. Readiness is verified separately with Info.
func Connect(cfg LNDConfig) (*LND, error) {
	var transport credentials.TransportCredentials
	if cfg.Insecure {
		transport = insecure.NewCredentials()
	} else {
		var err error
		transport, err = credentials.NewClientTLSFromFile(
			cfg.TLSCert, "",
		)
		if err != nil {
			return nil, fmt.Errorf("load LND TLS certificate: %w", err)
		}
	}
	mac, err := os.ReadFile(cfg.Macaroon)
	if err != nil {
		return nil, fmt.Errorf("load LND macaroon: %w", err)
	}
	conn, err := grpc.NewClient(
		cfg.Address, grpc.WithTransportCredentials(transport),
		grpc.WithPerRPCCredentials(macaroonCredential{
			hex: hex.EncodeToString(mac), secure: !cfg.Insecure,
		}),
	)
	if err != nil {
		return nil, err
	}
	return &LND{
		Conn: conn, Lightning: lnrpc.NewLightningClient(conn),
		Wallet:   walletrpc.NewWalletKitClient(conn),
		Router:   routerrpc.NewRouterClient(conn),
		Invoices: invoicesrpc.NewInvoicesClient(conn),
	}, nil
}

// Info checks that LND is on regtest and returns its current status.
func (l *LND) Info(ctx context.Context) (*lnrpc.GetInfoResponse, error) {
	info, err := l.Lightning.GetInfo(ctx, &lnrpc.GetInfoRequest{})
	if err != nil {
		return nil, err
	}
	if len(info.Chains) != 1 || info.Chains[0].Chain != "bitcoin" ||
		info.Chains[0].Network != "regtest" {

		return nil, fmt.Errorf("LND must run on Bitcoin regtest")
	}
	return info, nil
}

// Coins lists confirmed wallet coins available to back commitments.
func (l *LND) Coins(ctx context.Context) ([]Coin, error) {
	resp, err := l.Wallet.ListUnspent(ctx, &walletrpc.ListUnspentRequest{
		MinConfs: 1, MaxConfs: 1<<31 - 1,
	})
	if err != nil {
		return nil, err
	}
	coins := make([]Coin, 0, len(resp.Utxos))
	for _, utxo := range resp.Utxos {
		hash, err := chainhash.NewHashFromStr(utxo.Outpoint.TxidStr)
		if err != nil {
			hash, err = chainhash.NewHash(utxo.Outpoint.TxidBytes)
		}
		if err != nil {
			return nil, err
		}
		script, err := hex.DecodeString(utxo.PkScript)
		if err != nil {
			return nil, err
		}
		coins = append(coins, Coin{
			Outpoint: wire.OutPoint{Hash: *hash,
				Index: utxo.Outpoint.OutputIndex},
			Output:        wire.NewTxOut(utxo.AmountSat, script),
			Confirmations: utxo.Confirmations,
		})
	}
	return coins, nil
}

// Sign signs the wallet-owned inputs of a PSBT without changing its
// transaction.
func (l *LND) Sign(ctx context.Context, packet *psbt.Packet) (*psbt.Packet,
	error) {

	var raw bytes.Buffer
	if err := packet.Serialize(&raw); err != nil {
		return nil, err
	}
	resp, err := l.Wallet.SignPsbt(ctx, &walletrpc.SignPsbtRequest{
		FundedPsbt: raw.Bytes(),
	})
	if err != nil {
		return nil, err
	}
	return psbt.NewFromRawBytes(bytes.NewReader(resp.SignedPsbt), false)
}
