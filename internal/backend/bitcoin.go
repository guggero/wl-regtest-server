// Package backend connects the server to real Bitcoin Core and LND services.
package backend

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/wire/v2"
)

const (
	// RPCTimeout bounds one backend request, including an unresponsive
	// node.
	RPCTimeout = 15 * time.Second

	// maxRPCResponse limits accidental or maliciously large node responses.
	maxRPCResponse = 32 << 20
)

var (
	// ErrOutputSpent identifies an absent output in the authoritative UTXO
	// set.
	ErrOutputSpent = errors.New("output is not unspent")
)

// RPCError preserves Bitcoin Core's stable error code for recovery decisions.
type RPCError struct {
	Method  string
	Code    int
	Message string
}

// Error describes the failed node method without losing its numeric code.
func (e *RPCError) Error() string {
	return fmt.Sprintf("bitcoin %s (%d): %s", e.Method, e.Code, e.Message)
}

// Bitcoin provides a context-aware Bitcoin Core JSON-RPC connection.
type Bitcoin struct {
	URL      string
	User     string
	Password string
	Client   *http.Client
}

// ChainInfo is the chain identity and tip used for regtest admission.
type ChainInfo struct {
	Chain         string `json:"chain"`
	Blocks        uint32 `json:"blocks"`
	BestBlockHash string `json:"bestblockhash"`
}

// Coin is a confirmed or unconfirmed UTXO verified by Bitcoin Core.
type Coin struct {
	Outpoint      wire.OutPoint
	Output        *wire.TxOut
	Confirmations int64
}

// Call performs one JSON-RPC request and preserves node errors for diagnostics.
func (b *Bitcoin) Call(ctx context.Context, method string, params any,
	result any) error {

	body, err := json.Marshal(map[string]any{
		"jsonrpc": "1.0", "id": "wl-regtest", "method": method,
		"params": params,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, RPCTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, b.URL, bytes.NewReader(body),
	)
	if err != nil {
		return err
	}
	req.SetBasicAuth(b.User, b.Password)
	req.Header.Set("Content-Type", "application/json")
	client := b.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("bitcoin %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, maxRPCResponse)).Decode(
		&envelope,
	)
	if err != nil {
		return fmt.Errorf("bitcoin %s HTTP %d: %w",
			method, resp.StatusCode, err)
	}
	if envelope.Error != nil {
		return &RPCError{
			Method:  method,
			Code:    envelope.Error.Code,
			Message: envelope.Error.Message,
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bitcoin %s HTTP %d", method, resp.StatusCode)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(envelope.Result, result)
}

// Info queries the node's current chain identity and tip.
func (b *Bitcoin) Info(ctx context.Context) (*ChainInfo, error) {
	var info ChainInfo
	if err := b.Call(ctx, "getblockchaininfo", []any{}, &info); err != nil {
		return nil, err
	}
	return &info, nil
}

// UTXO checks an outpoint against the node's current UTXO set and mempool.
func (b *Bitcoin) UTXO(ctx context.Context, outpoint wire.OutPoint) (*Coin,
	error) {

	var result *struct {
		Value         float64 `json:"value"`
		Confirmations int64   `json:"confirmations"`
		Script        struct {
			Hex string `json:"hex"`
		} `json:"scriptPubKey"`
	}
	err := b.Call(ctx, "gettxout", []any{
		outpoint.Hash.String(), outpoint.Index, true,
	}, &result)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, fmt.Errorf("outpoint %s: %w", outpoint, ErrOutputSpent)
	}
	value, err := btcutil.NewAmount(result.Value)
	if err != nil {
		return nil, err
	}
	script, err := hex.DecodeString(result.Script.Hex)
	if err != nil {
		return nil, err
	}
	return &Coin{Outpoint: outpoint,
		Output:        wire.NewTxOut(int64(value), script),
		Confirmations: result.Confirmations}, nil
}

// Publish broadcasts a fully signed transaction, accepting exact replay.
func (b *Bitcoin) Publish(ctx context.Context, raw []byte) error {
	var id string
	err := b.Call(ctx, "sendrawtransaction", []any{
		hex.EncodeToString(raw), 0,
	}, &id)
	if err != nil &&
		strings.Contains(err.Error(), "already in block chain") {

		return nil
	}
	return err
}

// Transaction queries a known transaction's confirmation and canonical block.
func (b *Bitcoin) Transaction(ctx context.Context, txid string) (int64, string,
	error) {

	var result struct {
		Confirmations int64  `json:"confirmations"`
		BlockHash     string `json:"blockhash"`
	}
	err := b.Call(ctx, "getrawtransaction", []any{txid, true}, &result)
	return result.Confirmations, result.BlockHash, err
}

// BlockHeight returns the height of an actual canonical block rather than
// deriving it from a potentially stale cached tip and confirmation count.
func (b *Bitcoin) BlockHeight(ctx context.Context, hash string) (uint32,
	error) {

	var header struct {
		Height        uint32 `json:"height"`
		Confirmations int64  `json:"confirmations"`
	}
	if err := b.Call(ctx, "getblockheader", []any{
		hash, true,
	}, &header); err != nil {

		return 0, err
	}
	if header.Confirmations < 0 {
		return 0, errors.New("block is no longer canonical")
	}
	return header.Height, nil
}
