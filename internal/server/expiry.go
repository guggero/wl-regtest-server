package server

import (
	"context"
	"errors"
	"strings"

	"github.com/lightninglabs/wavelength/swaprpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// releaseCreditReservation restores spendable credits only for a reservation
// that has not been debited. Repeated reconciliation cannot release it twice.
func (s *Server) releaseCreditReservation(id, reason string) error {
	if id == "" {
		return nil
	}
	credit, err := get[creditRecord](s, "credit-operation/"+id)
	if err != nil {
		return err
	}
	if credit == nil {
		return errors.New("credit reservation missing")
	}
	if credit.Operation.State != swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_RESERVED {
		return nil
	}
	account, err := s.account(credit.Account)
	if err != nil {
		return err
	}
	if account.Reserved < credit.Operation.AmountSat {
		return errors.New("credit reservation underflow")
	}
	account.Reserved -= credit.Operation.AmountSat
	if err := s.put("credit-account/"+credit.Account, account); err != nil {
		return err
	}
	credit.Operation.State = swaprpc.CreditOperationState_CREDIT_OPERATION_STATE_RELEASED
	credit.Operation.LastError = reason
	credit.Operation.CompletedAt = timestamppb.New(s.cfg.Clock.Now())
	credit.Operation.UpdatedAt = credit.Operation.CompletedAt
	return s.put("credit-operation/"+id, credit)
}

// expireAwaitingSwaps releases credits for invoices whose funding window ended
// before any Lightning payment was initiated. Paying/claiming swaps must
// instead reconcile the authoritative Lightning result, even after their quote
// expires.
func (s *Server) expireAwaitingSwaps(ctx context.Context) error {
	return s.transact(ctx, func() error {
		for key := range s.state.Records {
			if !strings.HasPrefix(key, "in-swap/") {
				continue
			}
			swap, err := get[inSwap](s, key)
			if err != nil {
				return err
			}
			if swap.Phase != "awaiting-funding" || swap.Response.Expiry == nil || s.cfg.Clock.Now().Before(
				swap.Response.Expiry.AsTime(),
			) {

				continue
			}
			swap.Phase = "failed"
			swap.Failure = "swap funding window expired"
			if err := s.releaseCreditReservation(
				swap.CreditID, swap.Failure,
			); err != nil {

				return err
			}
			if err := s.put(key, swap); err != nil {
				return err
			}
		}
		return nil
	})
}
