package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/arkrpc"
)

const (
	// swapScanBatch bounds catch-up work after a long operator outage.
	swapScanBatch uint32 = 64

	// swapScanRewind revisits shallow reorganizations until a preimage is
	// known.
	swapScanRewind uint32 = 6
)

// chainClaim retains an irreversible hashlock disclosure and scan progress.
// Reorganizing its transaction cannot make the preimage secret again.
type chainClaim struct {
	NextHeight uint32
	Preimage   []byte
	TxID       string
}

// witnessPreimage extracts a matching hashlock from the exact funding input.
// The backend supplies only Bitcoin-validated mempool or block transactions.
func witnessPreimage(tx *backend.TransactionInputs, outpoint string,
	hash []byte) []byte {

	// A matching hash in some unrelated input is not evidence that this
	// funding output was claimed; restrict disclosure to the watched spend.
	for _, input := range tx.Inputs {
		if fmt.Sprintf("%s:%d", input.TxID, input.Vout) != outpoint {
			continue
		}
		for _, raw := range input.Witness {
			value, err := hex.DecodeString(raw)
			if err != nil || len(value) != 32 {
				continue
			}
			digest := sha256.Sum256(value)
			if bytes.Equal(digest[:], hash) {
				return value
			}
		}
	}
	return nil
}

// pollSwapChain recovers externally disclosed receive preimages after an
// operator outage. Confirmed blocks and the mempool are authoritative even
// when the receiver could not finalize an OOR package through the mailbox.
func (s *Server) pollSwapChain(ctx context.Context) error {
	// Snapshot only unresolved funded receives. Other swap phases either
	// have no claim output yet or already know how to settle the payment.
	s.mu.Lock()
	var candidates []*outSwap
	height := s.height
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "out-swap/") {
			continue
		}
		swap, err := get[outSwap](s, key)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		if swap.Phase == "funded" && len(
			swap.Preimage,
		) == 0 {

			candidates = append(candidates, swap)
		}
	}
	s.mu.Unlock()

	// Read the indexed exit state and saved cursor together, then perform
	// slow chain reads without holding the persistence lock.
	for _, swap := range candidates {
		s.mu.Lock()
		coin, err := get[vtxoRecord](s, "vtxo/"+swap.Outpoint)
		progress, progressErr := get[chainClaim](
			s, "chain-claim/"+swap.Outpoint,
		)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		if progressErr != nil {
			return progressErr
		}
		if coin == nil || coin.VTXO.Status != arkrpc.VTXOStatus_VTXO_STATUS_UNILATERAL_EXIT {
			continue
		}

		// Start no earlier than the funding record, and never discard a
		// known preimage: a reorg cannot make an observed secret
		// unknown again.
		if progress == nil {
			progress = &chainClaim{
				NextHeight: uint32(max(
					coin.VTXO.CreatedHeight, 0,
				)),
			}
		}
		if len(progress.Preimage) > 0 {
			continue
		}
		op := coin.VTXO.Outpoint
		if op == nil || len(op.Txid) != 32 {
			return fmt.Errorf("invalid watched outpoint")
		}

		// Use the transaction identifier already validated by the
		// indexer rather than interpreting a remote witness's address
		// or script metadata.
		separator := strings.LastIndex(swap.Outpoint, ":")
		if separator < 0 {
			return fmt.Errorf("invalid watched outpoint")
		}
		pending, err := s.cfg.Bitcoin.MempoolSpender(
			ctx, swap.Outpoint[:separator], op.Vout,
		)
		if err != nil && !backendNotFound(err) {
			return err
		}
		if pending != nil {
			progress.Preimage = witnessPreimage(
				pending, swap.Outpoint,
				swap.Request.PaymentHash,
			)
			if len(progress.Preimage) > 0 {
				progress.TxID = pending.TxID
			}
		}

		// Revisit shallow reorgs while bounding each catch-up pass so a
		// long outage cannot monopolize the worker and delay other
		// swaps.
		start := progress.NextHeight
		if start > swapScanRewind {
			start -= swapScanRewind
		}
		start = max(start, uint32(max(coin.VTXO.CreatedHeight, 0)))
		end := min(height, start+swapScanBatch-1)
		for h := start; h <= end && len(progress.Preimage) == 0; h++ {
			txs, err := s.cfg.Bitcoin.BlockTransactions(ctx, h)
			if err != nil {
				return err
			}
			for i := range txs {
				preimage := witnessPreimage(
					&txs[i], swap.Outpoint,
					swap.Request.PaymentHash,
				)
				if len(
					preimage,
				) > 0 {

					progress.Preimage = preimage
					progress.TxID = txs[i].TxID
					break
				}
			}
			progress.NextHeight = h + 1
		}

		// Retain both progress and any disclosure before the settlement
		// worker acts on it; recovery must survive another restart
		// between the two steps.
		if err := s.transact(ctx, func() error {
			return s.put("chain-claim/"+swap.Outpoint, progress)
		}); err != nil {

			return err
		}
	}
	return nil
}
