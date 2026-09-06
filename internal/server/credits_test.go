package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/lightninglabs/wavelength/swaprpc"
	"github.com/lightningnetwork/lnd/lnrpc"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// signCreditRequest uses the public client digest implementation to exercise
// the server boundary with an independently generated account signature.
func signCreditRequest(t *testing.T, s *Server, key *btcec.PrivateKey,
	req proto.Message) {

	t.Helper()
	digest, account, err := swaprpc.CreditAccountRequestDigest(req)
	require.NoError(t, err)
	nonce := make([]byte, 32)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	auth := &swaprpc.CreditAccountAuthorization{
		Nonce:         nonce,
		ExpiresAtUnix: s.cfg.Clock.Now().Add(time.Minute).Unix(),
	}
	signed := swaprpc.CreditAccountAuthDigest(
		account, digest, auth.ExpiresAtUnix, nonce,
	)
	sig, err := schnorr.Sign(key, signed[:])
	require.NoError(t, err)
	auth.Signature = sig.Serialize()
	require.NoError(t, swaprpc.SetCreditAccountAuthorization(req, auth))
}

// TestCreditAuthorization verifies account isolation, request binding, expiry,
// and nonce recovery across process restart without requiring a Lightning node.
func TestCreditAuthorization(t *testing.T) {
	dir := t.TempDir()
	s := testServer(t, dir)
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	req := &swaprpc.ListCreditsRequest{
		AccountPubkey: key.PubKey().SerializeCompressed(),
	}
	signCreditRequest(t, s, key, req)
	_, err = s.ListCredits(context.Background(), req)
	require.NoError(t, err)
	_, err = s.ListCredits(context.Background(), req)
	require.NoError(t, err)
	changed := proto.Clone(req).(*swaprpc.ListCreditsRequest)
	changed.Limit = 42
	_, err = s.ListCredits(context.Background(), changed)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	digest, account, err := swaprpc.CreditAccountRequestDigest(changed)
	require.NoError(t, err)
	auth := changed.AccountAuthorization
	signed := swaprpc.CreditAccountAuthDigest(
		account, digest, auth.ExpiresAtUnix, auth.Nonce,
	)
	sig, err := schnorr.Sign(key, signed[:])
	require.NoError(t, err)
	auth.Signature = sig.Serialize()
	restored := testServer(t, dir)
	_, err = restored.ListCredits(context.Background(), changed)
	require.Equal(t, codes.AlreadyExists, status.Code(err))
	expired := proto.Clone(req).(*swaprpc.ListCreditsRequest)
	expired.AccountAuthorization.ExpiresAtUnix = s.cfg.Clock.Now().Unix() -
		1
	_, err = s.ListCredits(context.Background(), expired)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
	foreign, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	wrong := proto.Clone(req).(*swaprpc.ListCreditsRequest)
	wrong.AccountPubkey = foreign.PubKey().SerializeCompressed()
	_, err = s.ListCredits(context.Background(), wrong)
	require.Equal(t, codes.Unauthenticated, status.Code(err))
}

// TestCreditLedger ensures reserved value cannot be debited twice or exceed
// finalized funding, including after restoring the durable ledger.
func TestCreditLedger(t *testing.T) {
	dir := t.TempDir()
	s := testServer(t, dir)
	r := &creditRecord{
		Account: "account",
		Operation: &swaprpc.CreditOperation{
			OperationId: "funding",
		},
	}
	require.NoError(t, s.transact(context.Background(), func() error {
		return s.postCredit(r, "credit", 1000)
	}))
	require.NoError(t, s.transact(context.Background(), func() error {
		return s.postCredit(r, "credit", 1000)
	}))
	require.Error(t, s.transact(context.Background(), func() error {
		return s.postCredit(r, "credit", 1001)
	}))
	r.Operation.OperationId = "redeem"
	require.Error(t, s.transact(context.Background(), func() error {
		return s.postCredit(r, "debit", 600)
	}))
	require.NoError(t, s.transact(context.Background(), func() error {
		a, err := s.account(r.Account)
		if err != nil {
			return err
		}
		a.Reserved = 600
		if err := s.put("credit-account/"+r.Account, a); err != nil {
			return err
		}
		return s.postCredit(r, "debit", 600)
	}))
	restored := testServer(t, dir)
	require.NoError(
		t, restored.transact(context.Background(), func() error {
			return restored.postCredit(r, "debit", 600)
		}),
	)
	a, err := restored.account(r.Account)
	require.NoError(t, err)
	require.EqualValues(t, 400, a.Finalized)
	require.Zero(t, a.Reserved)
	require.Len(t, a.Ledger, 2)
}

// ambiguousInvoiceNode models an invoice committed by LND whose AddInvoice
// response is lost or reported as an already-existing hash.
type ambiguousInvoiceNode struct {
	lnrpc.LightningClient
	mu      sync.Mutex
	invoice *lnrpc.Invoice
}

// LookupInvoice exposes the committed invoice independently of its add result.
func (n *ambiguousInvoiceNode) LookupInvoice(context.Context,
	*lnrpc.PaymentHash, ...grpc.CallOption) (*lnrpc.Invoice, error) {

	n.mu.Lock()
	defer n.mu.Unlock()
	if n.invoice == nil {
		return nil, status.Error(
			codes.Unknown, "there are no existing invoices",
		)
	}
	return proto.Clone(n.invoice).(*lnrpc.Invoice), nil
}

// AddInvoice persists the invoice while returning the legacy duplicate error.
func (n *ambiguousInvoiceNode) AddInvoice(_ context.Context, req *lnrpc.Invoice,
	_ ...grpc.CallOption) (*lnrpc.AddInvoiceResponse, error) {

	n.mu.Lock()
	defer n.mu.Unlock()
	n.invoice = proto.Clone(req).(*lnrpc.Invoice)
	hash := sha256.Sum256(req.RPreimage)
	n.invoice.RHash = hash[:]
	n.invoice.PaymentRequest = "committed-invoice"
	return nil, status.Error(
		codes.Unknown, "invoice with payment hash already exists",
	)
}

// TestCreditAmbiguousInvoice verifies recovery from legacy LND errors and
// concurrent settlement polling without duplicate credit creation.
func TestCreditAmbiguousInvoice(t *testing.T) {
	s := testServer(t, t.TempDir())
	node := &ambiguousInvoiceNode{}
	s.cfg.LND.Lightning = node
	key, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	req := &swaprpc.CreateCreditRequest{
		AccountPubkey:  key.PubKey().SerializeCompressed(),
		IdempotencyKey: "fund",
		AmountSat:      500,
		Source:         swaprpc.CreditFundingSource_CREDIT_FUNDING_SOURCE_LIGHTNING_RECEIVE,
	}
	signCreditRequest(t, s, key, req)
	funded, err := s.CreateCredit(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, "committed-invoice", funded.Invoice)
	node.mu.Lock()
	node.invoice.State = lnrpc.Invoice_SETTLED
	node.invoice.AmtPaidSat = 500
	node.mu.Unlock()
	results := make(chan error, 2)
	for range 2 {
		go func() {
			results <- s.pollCreditOperation(
				context.Background(), funded.OperationId,
			)
		}()
	}
	for range 2 {
		require.NoError(t, <-results)
	}
	listing := &swaprpc.ListCreditsRequest{AccountPubkey: req.AccountPubkey}
	signCreditRequest(t, s, key, listing)
	snapshot, err := s.ListCredits(context.Background(), listing)
	require.NoError(t, err)
	require.EqualValues(t, 500, snapshot.AvailableSat)
	require.Len(t, snapshot.LedgerEntries, 1)
}
