package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/arkrpc"
)

// checkVTXORoots requires every real commitment backing a VTXO to remain
// confirmed and unspent. A root already being unrolled is conservatively
// excluded from new operator-assisted transfers, including sibling branches.
func (s *Server) checkVTXORoots(ctx context.Context, record *vtxoRecord) error {
	for _, path := range record.VTXO.AncestryPaths {
		if path == nil || path.TreePath == nil ||
			path.TreePath.BatchOutpoint == nil ||
			len(path.TreePath.BatchOutpoint.Txid) != 32 {

			return errors.New("incomplete VTXO backing path")
		}
		out := path.TreePath.BatchOutpoint
		op := wire.OutPoint{Hash: [32]byte(out.Txid), Index: out.Vout}
		coin, err := s.cfg.Bitcoin.UTXO(ctx, op)
		if err != nil {
			return err
		}
		if coin.Confirmations < 1 {
			return fmt.Errorf("VTXO commitment %s is "+
				"unconfirmed", op)
		}
	}
	return nil
}

// validateOORChain checks Bitcoin's current backing coins and chain timelocks
// before any operator signature is released. Pure packet validation separately
// verifies the policy, values, scripts and participant signatures.
func (s *Server) validateOORChain(ctx context.Context,
	inputs map[chainhash.Hash]*oorInput) error {

	for _, input := range inputs {
		if err := s.checkVTXORoots(ctx, input.Record); err != nil {
			return err
		}
		path := input.Spend
		if path.RequiredLockTime > s.height {
			return errors.New(
				"OOR absolute timelock has not matured",
			)
		}
		if path.RequiredSequence != 0 && path.RequiredSequence&wire.SequenceLockTimeDisabled == 0 {
			// A CSV input requires its actual parent confirmation,
			// not the age of an off-chain commitment somewhere
			// earlier in its ancestry.
			op := input.Packet.UnsignedTx.TxIn[0].PreviousOutPoint
			coin, err := s.cfg.Bitcoin.UTXO(ctx, op)
			if err != nil {
				return err
			}
			if path.RequiredSequence&wire.SequenceLockTimeIsSeconds != 0 || coin.Confirmations < int64(path.RequiredSequence&wire.SequenceLockTimeMask) {
				return errors.New(
					"OOR relative timelock has not matured",
				)
			}
		}
	}
	return nil
}

// backendNotFound reports only an authoritative transaction-not-found result.
func backendNotFound(err error) bool {
	var rpcErr *backend.RPCError
	return errors.As(err, &rpcErr) && rpcErr.Code == -5
}

// pollVTXOChain reconciles reorgs and unilateral root spends without reviving
// inputs already consumed by OOR or a signed forfeit. Backend reads happen
// outside the persistence lock and updates recheck the current input status.
func (s *Server) pollVTXOChain(ctx context.Context) error {
	s.mu.Lock()
	records := make(map[string]*vtxoRecord)
	height := s.height
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "vtxo/") {
			continue
		}
		r, err := get[vtxoRecord](s, key)
		if err != nil {
			s.mu.Unlock()
			return err
		}
		switch r.VTXO.Status {
		case arkrpc.VTXOStatus_VTXO_STATUS_LIVE, arkrpc.VTXOStatus_VTXO_STATUS_UNCONFIRMED, arkrpc.VTXOStatus_VTXO_STATUS_UNILATERAL_EXIT:
			records[key] = r
		}
	}
	s.mu.Unlock()
	roots := make(map[wire.OutPoint]arkrpc.VTXOStatus)
	updates := make(map[string]arkrpc.VTXOStatus)
	for key, r := range records {
		state := arkrpc.VTXOStatus_VTXO_STATUS_LIVE
		for _, path := range r.VTXO.AncestryPaths {
			if path == nil || path.TreePath == nil ||
				path.TreePath.BatchOutpoint == nil ||
				len(path.TreePath.BatchOutpoint.Txid) != 32 {

				return errors.New("incomplete indexed ancestry")
			}
			out := path.TreePath.BatchOutpoint
			op := wire.OutPoint{
				Hash: [32]byte(
					out.Txid,
				),
				Index: out.Vout,
			}
			root, ok := roots[op]
			if !ok {
				coin, err := s.cfg.Bitcoin.UTXO(ctx, op)
				switch {
				case err == nil && coin.Confirmations > 0:
					root = arkrpc.VTXOStatus_VTXO_STATUS_LIVE

				case err == nil:
					root = arkrpc.VTXOStatus_VTXO_STATUS_UNCONFIRMED

				case errors.Is(err, backend.ErrOutputSpent):
					confs, _, err := s.cfg.Bitcoin.Transaction(ctx, op.Hash.String())
					if err != nil && !backendNotFound(err) {
						return err
					}
					if confs <= 0 {
						root = arkrpc.VTXOStatus_VTXO_STATUS_UNCONFIRMED
					} else {
						root = arkrpc.VTXOStatus_VTXO_STATUS_UNILATERAL_EXIT
					}

				default:
					return err
				}
				roots[op] = root
			}
			if root != arkrpc.VTXOStatus_VTXO_STATUS_LIVE {
				state = root
			}
		}
		if r.VTXO.BatchExpiryHeight <= int32(
			height+s.cfg.ExitDelay,
		) {

			state = arkrpc.VTXOStatus_VTXO_STATUS_UNILATERAL_EXIT
		}
		if state != r.VTXO.Status {
			updates[key] = state
		}
	}
	if len(updates) == 0 {
		return nil
	}
	return s.transact(ctx, func() error {
		for key, state := range updates {
			current, err := get[vtxoRecord](s, key)
			if err != nil {
				return err
			}
			if current == nil || current.VTXO.Status != records[key].VTXO.Status {
				continue
			}
			current.VTXO.Status = state
			if err := s.recordVTXO(
				key, current,
				arkrpc.VTXOOrigin_VTXO_ORIGIN_UNSPECIFIED,
			); err != nil {

				return err
			}
		}
		return nil
	})
}
