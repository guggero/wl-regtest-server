package server

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/tx/checkpoint"
	oortx "github.com/lightninglabs/wavelength/lib/tx/oor"
	"github.com/lightninglabs/wavelength/rpc/oorpb"
)

// oorInput binds a submitted checkpoint and signing paths to one live VTXO.
type oorInput struct {
	Record   *vtxoRecord
	Packet   *psbt.Packet
	Spend    *arkscript.SpendPath
	ArkSpend *arkscript.SpendPath
}

// validateOOR validates public transaction structure plus the operator's
// authoritative input set, checkpoint scripts and conserved output value. It
// does not mutate state or expose signatures.
// The caller must hold s.mu or have exclusive access to state. Returned
// bindings refer to the submitted packets and detached indexed records; chain
// availability and actual signatures require subsequent validation.
func (s *Server) validateOOR(ark *psbt.Packet, checkpoints []*psbt.Packet,
	descriptors []oorpb.SigningDescriptor,
	recipients []oortx.RecipientOutput) (map[chainhash.Hash]*oorInput,
	error) {

	// Bound package complexity before using the public structural
	// validator; operator policy and indexed ownership checks remain
	// separate below.
	if len(checkpoints) > maxRoundItems ||
		len(recipients) > maxRoundItems ||
		len(descriptors) != len(checkpoints) || len(recipients) == 0 {

		return nil, errors.New("invalid OOR item count")
	}
	if _, err := oortx.ValidateSubmitPackage(ark, checkpoints); err != nil {
		return nil, err
	}

	// Match descriptors by spent outpoint rather than arrival order, while
	// ensuring each checkpoint consumes one distinct descriptor.
	byOutpoint := make(map[wire.OutPoint]oorpb.SigningDescriptor)
	for _, descriptor := range descriptors {
		if _, exists := byOutpoint[descriptor.Outpoint]; exists {
			return nil, errors.New("duplicate signing descriptor")
		}
		byOutpoint[descriptor.Outpoint] = descriptor
	}

	// Resolve every checkpoint to a live indexed coin before accumulating
	// value; a well-formed package alone does not establish funding.
	inputs := make(map[chainhash.Hash]*oorInput)
	var inputValue int64
	for _, packet := range checkpoints {
		if len(packet.Inputs) != 1 ||
			len(packet.UnsignedTx.TxIn) != 1 ||
			len(packet.UnsignedTx.TxOut) != 2 {

			return nil, errors.New(
				"checkpoint must have one input and two " +
					"outputs",
			)
		}
		outpoint := packet.UnsignedTx.TxIn[0].PreviousOutPoint
		descriptor, exists := byOutpoint[outpoint]
		if !exists {
			return nil, errors.New("checkpoint descriptor missing")
		}
		delete(byOutpoint, outpoint)
		input, err := s.validateOORInput(packet, descriptor)
		if err != nil {
			return nil, fmt.Errorf("input %s: %w", outpoint, err)
		}
		inputs[packet.UnsignedTx.TxHash()] = input
		value := int64(input.Record.VTXO.ValueSat)
		if value <= 0 || value > btcutil.MaxSatoshi-inputValue {
			return nil, errors.New("OOR input value overflow")
		}
		inputValue += value
	}

	// Every non-anchor output must match its recipient declaration and
	// compiled policy, with no undeclared destination consuming input
	// value.
	if len(recipients) != len(ark.UnsignedTx.TxOut)-1 {
		return nil, errors.New(
			"recipient count differs from Ark outputs",
		)
	}
	var outputValue int64
	for i, recipient := range recipients {
		output := ark.UnsignedTx.TxOut[i]
		if !bytes.Equal(output.PkScript, recipient.PkScript) ||
			output.Value != int64(recipient.Value) ||
			output.Value < s.cfg.MinAmount ||
			output.Value > btcutil.MaxSatoshi-outputValue {

			return nil, errors.New("invalid OOR recipient output")
		}
		policy, err := s.outputPolicy(recipient.VTXOPolicyTemplate)
		if err != nil {
			return nil, err
		}
		script, err := policy.PkScript()
		if err != nil || !bytes.Equal(script, output.PkScript) {
			return nil, errors.New(
				"recipient policy differs from output",
			)
		}
		outputValue += output.Value
	}

	// This fixture subsidizes on-chain fees separately; the virtual
	// transfer itself must conserve the entire admitted input value.
	if inputValue != outputValue {
		return nil, errors.New(
			"OOR transaction does not conserve value",
		)
	}
	return inputs, nil
}

// outputPolicy compiles the exact policy accepted for both round and OOR
// outputs, requiring every cooperative path to retain the operator.
func (s *Server) outputPolicy(raw []byte) (*arkscript.PolicyTemplate, error) {
	policy, err := arkscript.DecodePolicyTemplate(raw)
	if err != nil {
		return nil, err
	}

	// Compilation alone accepts policies outside this operator's terms.
	// Validate operator participation and the minimum unilateral exit
	// delay.
	nodes := make([]arkscript.Node, len(policy.Leaves))
	for i, leaf := range policy.Leaves {
		nodes[i] = leaf.Node
	}
	if err := arkscript.ValidatePolicy(
		nodes, arkscript.PolicyValidationOpts{
			OperatorKey: s.key.PubKey(), MinExitDelay: s.cfg.ExitDelay,
		},
	); err != nil {

		return nil, err
	}
	return policy, nil
}

// validateOORInput binds signing paths to persisted policy and reconstructs
// the checkpoint output independently of client-supplied PSBT metadata.
// The caller must first enforce the public package shape and one-input
// checkpoint structure, and must hold s.mu while consulting indexed state.
func (s *Server) validateOORInput(packet *psbt.Packet,
	descriptor oorpb.SigningDescriptor) (*oorInput, error) {

	// Only live, unreserved coins with enough exit runway can enter a new
	// session. Indexed status prevents competing off-chain spends.
	record, err := get[vtxoRecord](s, "vtxo/"+descriptor.Outpoint.String())
	if err != nil {
		return nil, err
	}
	if record == nil || record.VTXO.Status != arkrpc.VTXOStatus_VTXO_STATUS_LIVE || record.VTXO.BatchExpiryHeight <= int32(
		s.height+s.cfg.ExitDelay,
	) {

		return nil, errors.New("input VTXO is not spendable")
	}
	if _, exists := s.state.Records["reserved/"+descriptor.Outpoint.String()]; exists {
		return nil, errors.New("input VTXO is reserved")
	}

	// Bind client PSBT metadata to the authoritative coin before it reaches
	// Taproot hashing; altered amounts or scripts would change the digest.
	previous := packet.Inputs[0].WitnessUtxo
	if previous == nil || previous.Value != int64(record.VTXO.ValueSat) ||
		!bytes.Equal(previous.PkScript, record.VTXO.PkScript) ||
		!bytes.Equal(record.Policy, descriptor.VTXOPolicyTemplate) {

		return nil, errors.New(
			"input does not match authoritative VTXO",
		)
	}

	// The checkpoint must spend through a real leaf requiring this
	// operator, not merely carry a plausible script supplied by the
	// requester.
	policy, err := arkscript.DecodePolicyTemplate(record.Policy)
	if err != nil {
		return nil, err
	}
	spend, err := arkscript.DecodeSpendPath(descriptor.SpendPath)
	if err != nil {
		return nil, err
	}
	if err := spend.VerifyBindsToPkScript(previous.PkScript); err != nil {
		return nil, err
	}
	keys, err := arkscript.SigningKeysForSpendPath(policy, spend)
	if err != nil || !hasKey(keys, s.key.PubKey()) {
		return nil, errors.New("checkpoint spend must include operator")
	}

	// Checkpoint ownership may retain a subset of the original signers, but
	// must include both the operator and an owner from that original set.
	owner, err := arkscript.DecodeLeafTemplate(descriptor.OwnerLeafPolicy)
	if err != nil {
		return nil, err
	}
	ownerKeys, err := arkscript.SigningKeys(owner.Node)
	if err != nil || len(ownerKeys) < 2 ||
		!hasKey(ownerKeys, s.key.PubKey()) {

		return nil, errors.New(
			"checkpoint owner leaf needs operator and owner",
		)
	}
	for _, key := range ownerKeys {
		if !hasKey(keys, key) {
			return nil, errors.New(
				"checkpoint owner key is not an input signer",
			)
		}
	}

	// Rebuild the checkpoint using the public construction so its timeout
	// and owner branches cannot be substituted through PSBT output
	// metadata.
	result, err := checkpoint.BuildPSBT(arkscript.CheckpointPolicy{
		OperatorKey: s.key.PubKey(), CSVDelay: checkpoint.MinCheckpointCSVDelay,
	}, checkpoint.Input{
		SpentVTXO: checkpoint.SpentVTXORef{
			Outpoint: descriptor.Outpoint, Output: previous,
		}, OwnerLeafPolicy: descriptor.OwnerLeafPolicy,
	})
	if err != nil {
		return nil, err
	}
	if packet.UnsignedTx.Version != result.PSBT.UnsignedTx.Version || !bytes.Equal(
		packet.UnsignedTx.TxOut[0].PkScript,
		result.PSBT.UnsignedTx.TxOut[0].PkScript,
	) || packet.UnsignedTx.TxOut[0].Value != previous.Value || !bytes.Equal(
		packet.Outputs[0].TaprootTapTree, result.TapTreeEncoded,
	) {

		return nil, errors.New(
			"checkpoint differs from operator construction",
		)
	}

	// Return the operator-reconstructed owner branch for signing the Ark
	// spend, ensuring both stages use the same checkpoint commitment.
	leaf, err := oortx.BuildTaprootTapLeafScript(
		result.TapTreeEncoded, result.OwnerLeafScript,
	)
	if err != nil {
		return nil, err
	}
	return &oorInput{Record: record, Packet: packet, Spend: spend,
		ArkSpend: &arkscript.SpendPath{SpendInfo: &arkscript.SpendInfo{
			WitnessScript: leaf.Script, ControlBlock: leaf.ControlBlock,
		}}}, nil
}

// hasKey compares script keys by their x-only identities, as tapscript does.
func hasKey(keys []*btcec.PublicKey, target *btcec.PublicKey) bool {
	for _, key := range keys {
		if bytes.Equal(
			schnorr.SerializePubKey(key),
			schnorr.SerializePubKey(target),
		) {

			return true
		}
	}
	return false
}
