package backend

import "context"

// TransactionInputs retains the Bitcoin-validated witness of each transaction
// input, which can reveal a hashlock preimage during unilateral recovery.
type TransactionInputs struct {
	TxID   string `json:"txid"`
	Inputs []struct {
		TxID    string   `json:"txid"`
		Vout    uint32   `json:"vout"`
		Witness []string `json:"txinwitness"`
	} `json:"vin"`
}

// BlockTransactions reads inputs from one canonical block without requiring a
// wallet import for the operator's off-chain outputs.
func (b *Bitcoin) BlockTransactions(ctx context.Context,
	height uint32) ([]TransactionInputs, error) {

	// Resolve the height on the active chain for each poll. A cached block
	// hash would keep scanning a disconnected branch after a reorg.
	var hash string
	if err := b.Call(ctx, "getblockhash", []any{
		height,
	}, &hash); err != nil {

		return nil, err
	}

	// Verbosity two includes input witnesses, which recovery needs to
	// extract a hashlock preimage without importing every virtual output
	// into a wallet.
	var block struct {
		Transactions []TransactionInputs `json:"tx"`
	}
	err := b.Call(ctx, "getblock", []any{hash, 2}, &block)
	return block.Transactions, err
}

// MempoolSpender reads an actual mempool spend of an outpoint if one exists.
// Callers retry races between the spend lookup and transaction retrieval.
func (b *Bitcoin) MempoolSpender(ctx context.Context, txid string,
	vout uint32) (*TransactionInputs, error) {

	// Query by the exact prevout instead of scanning every mempool
	// transaction. An absent spender is a normal observation, not a failed
	// recovery attempt.
	var spends []struct {
		TxID string `json:"spendingtxid"`
	}
	err := b.Call(ctx, "gettxspendingprevout", []any{
		[]any{
			map[string]any{
				"txid": txid,
				"vout": vout,
			},
		},
	}, &spends)
	if err != nil {
		return nil, err
	}
	if len(spends) == 0 || spends[0].TxID == "" {
		return nil, nil
	}

	// The spender can leave the mempool between RPCs. Propagate that lookup
	// failure so the caller can retry or find the confirmed spend in a
	// block.
	var tx TransactionInputs
	if err := b.Call(ctx, "getrawtransaction", []any{
		spends[0].TxID, true,
	}, &tx); err != nil {

		return nil, err
	}
	return &tx, nil
}
