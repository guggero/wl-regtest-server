package server

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	oortx "github.com/lightninglabs/wavelength/lib/tx/oor"
)

// packetPrevouts requires a complete, duplicate-free input set. Callers must
// first compare witness outputs against their authoritative coin records.
func packetPrevouts(packet *psbt.Packet) (*txscript.MultiPrevOutFetcher,
	error) {

	// Signature hashing must have one metadata entry per transaction input;
	// otherwise the PSBT could describe a different spend than its
	// transaction.
	if packet == nil || packet.UnsignedTx == nil ||
		len(packet.Inputs) != len(packet.UnsignedTx.TxIn) {

		return nil, errors.New("invalid PSBT input set")
	}

	// Reject aliases and missing amounts before constructing the shared
	// prevout view used by Taproot signature hashing.
	fetcher := txscript.NewMultiPrevOutFetcher(nil)
	for i, input := range packet.UnsignedTx.TxIn {
		output := packet.Inputs[i].WitnessUtxo
		if output == nil || output.Value <= 0 ||
			fetcher.FetchPrevOutput(input.PreviousOutPoint) != nil {

			return nil, errors.New(
				"missing or duplicate PSBT prevout",
			)
		}
		fetcher.AddPrevOut(input.PreviousOutPoint, output)
	}
	return fetcher, nil
}

// signPacketInput signs only the designated script leaf with SIGHASH_DEFAULT.
// The supplied path must bind the authoritative witness output; callers
// validate policy authorization and the transaction's value conservation before
// signing.
// It mutates packet in place and returns an error for conflicting signature
// metadata. Callers must discard or roll back the packet on error.
func signPacketInput(packet *psbt.Packet, index int, key *btcec.PrivateKey,
	path *arkscript.SpendPath) error {

	// SIGHASH_DEFAULT commits to every input, so even signing one input
	// requires complete prevout information for the whole transaction.
	fetcher, err := packetPrevouts(packet)
	if err != nil {
		return err
	}
	if index < 0 || index >= len(packet.Inputs) {
		return errors.New("invalid signing input index")
	}

	// Bind the requested leaf to the funded output and refuse finalized or
	// key-path metadata that would change how the signature is interpreted.
	input := &packet.Inputs[index]
	if err := path.VerifyBindsToPkScript(
		input.WitnessUtxo.PkScript,
	); err != nil {

		return err
	}
	if input.SighashType != txscript.SigHashDefault ||
		len(input.TaprootKeySpendSig) != 0 ||
		len(input.FinalScriptWitness) != 0 {

		return errors.New("expected unfinalized script-path input")
	}

	// Existing partials must describe this same leaf and must not already
	// contain our key; signing twice would conceal a conflicting
	// transcript.
	leaf := txscript.NewBaseTapLeaf(path.WitnessScript)
	leafHash := leaf.TapHash()
	publicKey := schnorr.SerializePubKey(key.PubKey())
	for _, signature := range input.TaprootScriptSpendSig {
		if signature == nil ||
			signature.SigHash != txscript.SigHashDefault ||
			!bytes.Equal(signature.LeafHash, leafHash[:]) {

			return errors.New("conflicting PSBT signature metadata")
		}
		if bytes.Equal(signature.XOnlyPubKey, publicKey) {
			return errors.New("signing key already present in PSBT")
		}
	}

	// Only after the metadata agrees do we commit the operator key to the
	// complete transaction and this particular script leaf.
	hashes := txscript.NewTxSigHashes(packet.UnsignedTx, fetcher)
	digest, err := txscript.CalcTapscriptSignaturehash(
		hashes, txscript.SigHashDefault, packet.UnsignedTx, index,
		fetcher, leaf,
	)
	if err != nil {
		return err
	}
	signature, err := schnorr.Sign(key, digest)
	if err != nil {
		return err
	}

	// PSBT map keys must be unique. The client normally attached this leaf
	// already; replace its metadata instead of appending a duplicate key.
	input.TaprootLeafScript = []*psbt.TaprootTapLeafScript{{
		Script: path.WitnessScript, ControlBlock: path.ControlBlock,
		LeafVersion: txscript.BaseLeafVersion,
	}}
	if len(path.Conditions) > 0 {
		if err := arkscript.PutConditionWitnessPSBTInput(
			packet, index, path.Conditions,
		); err != nil {

			return err
		}
	}
	input.TaprootScriptSpendSig = append(
		input.TaprootScriptSpendSig, &psbt.TaprootScriptSpendSig{
			XOnlyPubKey: publicKey, LeafHash: leafHash[:],
			Signature: signature.Serialize(), SigHash: txscript.SigHashDefault,
		},
	)
	return nil
}

// signedPacket reconstructs the exact witness transaction with the public
// condition-aware builder and executes every input before returning it.
// The packet is not finalized in place. Its witness prevouts must already have
// been checked against authoritative funding records.
func signedPacket(packet *psbt.Packet) (*wire.MsgTx, error) {
	// Retain the packet as a signing transcript; witnesses are assembled on
	// a copy using the same complete prevout view used during signing.
	fetcher, err := packetPrevouts(packet)
	if err != nil {
		return nil, err
	}
	tx := packet.UnsignedTx.Copy()
	for i := range tx.TxIn {
		tx.TxIn[i].Witness, err = oortx.BuildTaprootWitness(
			packet.Inputs[i],
		)
		if err != nil {
			return nil, fmt.Errorf("input %d witness: %w", i, err)
		}
	}

	// A collection of signatures is not sufficient evidence of
	// spendability. Execute the assembled witnesses, including any hashlock
	// conditions.
	if err := verifyTransaction(tx, fetcher); err != nil {
		return nil, err
	}
	return tx, nil
}
