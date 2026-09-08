package server

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/tree"
)

// nodeSigning retains the complete, immutable nonce transcript for one node.
// Secret nonces are erased as soon as their one partial signature is committed.
type nodeSigning struct {
	Secret        []byte
	Public        []byte
	Peers         map[string][]byte
	Aggregate     []byte
	Partial       []byte
	CombinedPoint []byte
	Signature     []byte
}

// newNodeSigning creates an independent nonce for one 32-byte transaction
// digest. The caller must persist the returned secret before exposing its
// public nonce, and must use it only with that digest and signing key.
func newNodeSigning(key *btcec.PrivateKey, digest []byte) (*nodeSigning,
	error) {

	if len(digest) != 32 {
		return nil, errors.New("invalid tree signature digest")
	}

	// Mix the signing key and message into fresh nonce generation so each
	// node has an independent signing session, including across restarts.
	nonce, err := musig2.GenNonces(
		musig2.WithPublicKey(key.PubKey()),
		musig2.WithNonceSecretKeyAux(key),
		musig2.WithNonceMessageAux([32]byte(digest)),
	)
	if err != nil {
		return nil, fmt.Errorf("create tree nonce: %w", err)
	}
	return &nodeSigning{Secret: nonce.SecNonce[:], Public: nonce.PubNonce[:],
		Peers: make(map[string][]byte)}, nil
}

// bindNonces binds all peer nonces before producing the operator partial. A
// different peer transcript is never accepted after the first binding. The
// caller must serialize access and persist this mutation before releasing the
// partial; root is the Taproot script root, or empty for a BIP86 output.
func (n *nodeSigning) bindNonces(key *btcec.PrivateKey, node *tree.Node,
	digest, root []byte, peers map[string][]byte) error {

	// Retries may return the original partial, but must never reuse its
	// secret nonce with a different aggregate nonce.
	if len(n.Partial) > 0 {
		if len(peers) != len(n.Peers) {
			return errors.New("nonce transcript changed")
		}
		for id, nonce := range peers {
			if !bytes.Equal(nonce, n.Peers[id]) {
				return errors.New("nonce transcript changed")
			}
		}
		return nil
	}

	// Require exactly the tree participants before aggregation. An omitted
	// or additional peer would change the signing session.
	nonces := [][musig2.PubNonceSize]byte{
		[musig2.PubNonceSize]byte(n.Public),
	}
	for _, peer := range node.CoSigners {
		if peer.IsEqual(key.PubKey()) {
			continue
		}
		id := hex.EncodeToString(peer.SerializeCompressed())
		nonce := peers[id]
		if len(nonce) != musig2.PubNonceSize {
			return fmt.Errorf("missing or invalid nonce for %s", id)
		}
		nonces = append(nonces, [musig2.PubNonceSize]byte(nonce))
	}
	if len(peers) != len(nonces)-1 || len(n.Secret) != musig2.SecNonceSize {
		return errors.New("invalid nonce transcript")
	}

	// The key ordering and tweak must match the tree output construction;
	// an untweaked signature would not spend that output.
	aggregate, err := musig2.AggregateNonces(nonces)
	if err != nil {
		return fmt.Errorf("aggregate tree nonces: %w", err)
	}
	opts := []musig2.SignOption{musig2.WithSortedKeys()}
	if len(root) > 0 {
		opts = append(opts, musig2.WithTaprootSignTweak(root))
	} else {
		opts = append(opts, musig2.WithBip86SignTweak())
	}
	partial, err := musig2.Sign(
		[musig2.SecNonceSize]byte(n.Secret), key, aggregate,
		node.CoSigners, [32]byte(digest), opts...,
	)
	if err != nil {
		return fmt.Errorf("sign tree node: %w", err)
	}

	// Replace the secret with the reproducible public transcript.
	// Persisting this transition makes retries return the same partial
	// without signing again.
	var encoded bytes.Buffer
	if err := partial.Encode(&encoded); err != nil {
		return err
	}
	n.Secret = nil
	n.Aggregate, n.Partial = aggregate[:], encoded.Bytes()
	n.CombinedPoint = partial.R.SerializeCompressed()
	n.Peers = peers
	return nil
}

// combine verifies every peer partial against its committed public nonce and
// verifies the resulting Schnorr signature against the actual tree output key.
// The caller must pass the same key, node, 32-byte digest and script root used
// for binding, serialize access, and persist the resulting signature before
// publishing it. Empty root selects the BIP86 tweak.
func (n *nodeSigning) combine(key *btcec.PublicKey, node *tree.Node,
	digest, root []byte, peers map[string][]byte) (*schnorr.Signature,
	error) {

	// Combination is allowed only after our nonce transcript is fixed; peer
	// partials are meaningful only relative to that committed session.
	if len(n.Aggregate) != musig2.PubNonceSize || len(n.Partial) != 32 {
		return nil, errors.New("nonces have not been bound")
	}
	var own musig2.PartialSignature
	if err := own.Decode(bytes.NewReader(n.Partial)); err != nil {
		return nil, err
	}
	partials := []*musig2.PartialSignature{&own}

	// Verification and combination must use the identical sorting and
	// Taproot tweak rules used when producing each partial.
	opts := []musig2.SignOption{musig2.WithSortedKeys()}
	combine := musig2.WithBip86TweakedCombine(
		[32]byte(digest), node.CoSigners, true,
	)
	if len(root) > 0 {
		opts = append(opts, musig2.WithTaprootSignTweak(root))
		combine = musig2.WithTaprootTweakedCombine(
			[32]byte(digest), node.CoSigners, root, true,
		)
	} else {
		opts = append(opts, musig2.WithBip86SignTweak())
	}

	// Verify each expected signer against its previously bound nonce.
	// Checking only the final signature would hide which transcript was
	// invalid.
	for _, peer := range node.CoSigners {
		if peer.IsEqual(key) {
			continue
		}
		id := hex.EncodeToString(peer.SerializeCompressed())
		raw, nonce := peers[id], n.Peers[id]
		if len(raw) != 32 || len(nonce) != musig2.PubNonceSize {
			return nil, fmt.Errorf("missing partial signature for "+
				"%s", id)
		}
		var partial musig2.PartialSignature
		if err := partial.Decode(bytes.NewReader(raw)); err != nil {
			return nil, err
		}
		if !partial.Verify(
			[musig2.PubNonceSize]byte(nonce),
			[musig2.PubNonceSize]byte(n.Aggregate), node.CoSigners,
			peer, [32]byte(digest), opts...,
		) {

			return nil, errors.New("invalid tree partial signature")
		}
		partials = append(partials, &partial)
	}
	if len(peers) != len(partials)-1 {
		return nil, errors.New("unexpected tree partial signatures")
	}

	// The aggregate must spend the actual tweaked output key, and a retry
	// must reproduce the signature already recorded for this node.
	point, err := btcec.ParsePubKey(n.CombinedPoint)
	if err != nil {
		return nil, err
	}
	sig := musig2.CombineSigs(point, partials, combine)
	finalKey, err := tree.ComputeFinalKey(node.CoSigners, root)
	if err != nil {
		return nil, err
	}
	if !sig.Verify(digest, finalKey) {
		return nil, errors.New("invalid aggregate tree signature")
	}
	if len(n.Signature) > 0 && !bytes.Equal(n.Signature, sig.Serialize()) {
		return nil, errors.New("tree signature transcript changed")
	}
	n.Signature = sig.Serialize()
	return sig, nil
}

// standardPath extracts the collaborative branch of a standard boarding/VTXO.
// raw must encode a StandardVTXO policy. The returned path is newly compiled;
// custom policies fail rather than selecting an arbitrary cooperative leaf.
func standardPath(raw []byte) (*arkscript.SpendPath,
	*arkscript.StandardVTXOParams, error) {

	// Decode the typed policy before selecting its leaf: arbitrary policy
	// trees must not be mistaken for the standard owner/operator agreement.
	policy, err := arkscript.DecodePolicyTemplate(raw)
	if err != nil {
		return nil, nil, err
	}
	params, err := arkscript.DecodeStandardVTXOParams(policy)
	if err != nil {
		return nil, nil, err
	}

	// Resolve the collaborative leaf through the public compiler so its
	// script and control block bind to the same policy as the client.
	compiled, err := policy.Compile()
	if err != nil {
		return nil, nil, err
	}
	path, err := compiled.SpendPathForNode(&arkscript.Multisig{
		Keys: []*btcec.PublicKey{params.OwnerKey, params.OperatorKey},
	}, nil)
	return path, params, err
}

// verifyTransaction executes every input against its authoritative prevout.
// prev must supply all inputs for Taproot hashing. Script execution checks
// witness validity and transaction lock fields, but does not establish parent
// confirmation, chain maturity, or unspentness.
func verifyTransaction(tx *wire.MsgTx, prev txscript.PrevOutputFetcher) error {
	// Use Bitcoin script execution as the final boundary, with the supplied
	// amounts and scripts participating in Taproot signature verification.
	hashes := txscript.NewTxSigHashes(tx, prev)
	for i, in := range tx.TxIn {
		out := prev.FetchPrevOutput(in.PreviousOutPoint)
		if out == nil {
			return errors.New("missing transaction prevout")
		}
		vm, err := txscript.NewEngine(
			out.PkScript, tx, i, txscript.StandardVerifyFlags, nil,
			hashes, out.Value, prev,
		)
		if err != nil {
			return fmt.Errorf("input %d: %w", i, err)
		}
		if err := vm.Execute(); err != nil {
			return fmt.Errorf("input %d: %w", i, err)
		}
	}
	return nil
}
