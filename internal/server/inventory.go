package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/v2"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/google/uuid"
	"github.com/guggero/wl-regtest-server/internal/backend"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/lib/tree"
	oortx "github.com/lightninglabs/wavelength/lib/tx/oor"
	"github.com/lightninglabs/wavelength/rpc/oorpb"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// inventoryDomain separates treasury VTXO ownership from operator
	// signing.
	inventoryDomain = "inventory/owner"

	// inventoryLeaves provides independent inputs for concurrent test
	// payments.
	inventoryLeaves = 8
)

// inventoryPolicy derives the ordinary VTXO policy used for treasury change.
func (s *Server) inventoryPolicy() (*arkscript.PolicyTemplate, error) {
	return arkscript.StandardVTXOTemplate(
		s.deriveKey(inventoryDomain).PubKey(), s.key.PubKey(),
		s.cfg.ExitDelay,
	)
}

// inventoryCoins returns live treasury VTXOs whose participant keys are known.
// It excludes reservations and near-expiry outputs just like client admission.
// The caller must hold s.mu. Results are detached records; this helper
// filters indexed state but leaves actual root checks to transfer admission.
func (s *Server) inventoryCoins() ([]*vtxoRecord, error) {
	// Treasury ownership is established by a saved script/key mapping, not
	// by sharing the operator key that appears in every client policy.
	var coins []*vtxoRecord
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "vtxo/") {
			continue
		}
		r, err := get[vtxoRecord](s, key)
		if err != nil {
			return nil, err
		}
		v := r.VTXO
		if v.Status != arkrpc.VTXOStatus_VTXO_STATUS_LIVE || v.BatchExpiryHeight <= int32(
			s.height+s.cfg.ExitDelay,
		) || v.ChainDepth >= 24 {

			continue
		}
		op, err := indexedOutpoint(v)
		if err != nil {
			return nil, err
		}
		if _, locked := s.state.Records["reserved/"+op.String()]; locked {
			continue
		}
		domain, err := get[string](
			s, "inventory-script/"+hex.EncodeToString(v.PkScript),
		)
		if err != nil {
			return nil, err
		}
		if domain != nil {
			coins = append(coins, r)
		}
	}

	// Order by transaction identity to reduce selection dependence on map
	// iteration; siblings with the same txid need no relative priority
	// here.
	sort.Slice(coins, func(i, j int) bool {
		return bytes.Compare(
			coins[i].VTXO.Outpoint.Txid,
			coins[j].VTXO.Outpoint.Txid,
		) < 0
	})
	return coins, nil
}

// indexedOutpoint decodes an indexer output without changing hash byte order.
func indexedOutpoint(v *arkrpc.VTXO) (wire.OutPoint, error) {
	if v == nil || v.Outpoint == nil || len(v.Outpoint.Txid) != 32 {
		return wire.OutPoint{}, errors.New("invalid indexed outpoint")
	}
	return wire.OutPoint{
		Hash: [32]byte(
			v.Outpoint.Txid,
		),
		Index: v.Outpoint.Vout,
	}, nil
}

// ensureInventory builds a real treasury-funded round when spendable inventory
// falls below half its target. Pending commitments prevent duplicate funding.
func (s *Server) ensureInventory(ctx context.Context) error {
	// Bound wallet work while serializing the refill decision with other
	// funding operations; two callers must not both refill the same
	// deficit.
	ctx, cancel := context.WithTimeout(ctx, backend.RPCTimeout)
	defer cancel()
	return s.transact(ctx, func() error {
		coins, err := s.inventoryCoins()
		if err != nil {
			return err
		}
		var available uint64
		for _, coin := range coins {
			available += coin.VTXO.ValueSat
		}
		if available >= uint64(s.cfg.InventoryAmount/2) {
			return nil
		}

		// A pending treasury round is already replenishing inventory.
		// Wait for its confirmation rather than spending more on-chain
		// coins each poll.
		for key := range s.state.Records {
			if !strings.HasPrefix(key, "round/") {
				continue
			}
			r, err := get[roundRecord](s, key)
			if err != nil {
				return err
			}
			if r.Owner == s.id && r.Status != roundpb.RoundLifecycleStatus_ROUND_STATUS_CONFIRMED && r.Phase != "dead" {
				return nil
			}
		}

		// Register the spend-owner derivation before issuing treasury
		// leaves so selection can recognize both initial inventory and
		// later OOR change.
		policy, err := s.inventoryPolicy()
		if err != nil {
			return err
		}
		raw, err := policy.Encode()
		if err != nil {
			return err
		}
		script, err := policy.PkScript()
		if err != nil {
			return err
		}
		if err := s.put(
			"inventory-script/"+hex.EncodeToString(script),
			inventoryDomain,
		); err != nil {

			return err
		}

		// Split the refill into independent leaves for concurrent
		// payments. Per-leaf tree cosigners keep leaf lookup distinct
		// even with one spend policy.
		id := uuid.New()
		owners := make(map[string]*btcec.PrivateKey)
		r := &roundRecord{ID: id.String(), Owner: s.id, Request: &roundpb.JoinRoundRequest{},
			Quote: &roundpb.JoinRoundQuote{}, Signing: make(map[string]*nodeSigning),
			Status: roundpb.RoundLifecycleStatus_ROUND_STATUS_IN_FLIGHT, Created: s.cfg.Clock.Now().Unix()}
		for i := 0; i < inventoryLeaves; i++ {
			owner := s.deriveKey(fmt.Sprintf(
				"%s/inventory-signer/%d", r.ID, i,
			))
			owners[hex.EncodeToString(
				owner.PubKey().SerializeCompressed(),
			)] = owner
			value := s.cfg.InventoryAmount / inventoryLeaves
			if i == 0 {
				value += s.cfg.InventoryAmount % inventoryLeaves
			}
			r.Request.VtxoRequests = append(
				r.Request.VtxoRequests, &roundpb.VTXORequest{
					PolicyTemplate:  raw,
					SigningKey:      owner.PubKey().SerializeCompressed(),
					TargetAmountSat: value,
					FixedAmount:     true,
				},
			)
			r.Quote.VtxoQuotes = append(
				r.Quote.VtxoQuotes, &roundpb.VTXOQuote{
					PkScript:     script,
					AmountSat:    value,
					RecipientKey: owner.PubKey().SerializeCompressed(),
				},
			)
		}

		// Use the same funded commitment construction as client rounds.
		// The fixture knows both sides of the tree signing protocol for
		// its own inventory.
		if err := s.buildBatch(ctx, r); err != nil {
			return err
		}
		r.Sigs = &roundpb.ClientVTXOAggSigs{
			RoundId: id[:],
			AggSigs: make(map[string][]byte),
		}
		operator := s.deriveKey(r.ID + "/tree")
		err = walkRoundTree(
			r,
			func(t *tree.Tree, node *tree.Node, id string,
				digest []byte) error {

				// Give each participant an independent nonce
				// for this node; knowing all the private keys
				// does not permit reusing MuSig2 nonce
				// sessions.
				participants := make(map[string]*nodeSigning)
				peerNonces := make(map[string][]byte)
				signing := r.Signing[id]
				operatorID := hex.EncodeToString(
					operator.PubKey().SerializeCompressed(),
				)
				for _, peer := range node.CoSigners {
					peerID := hex.EncodeToString(
						peer.SerializeCompressed(),
					)
					if peerID == operatorID {
						continue
					}
					owner := owners[peerID]
					if owner == nil {
						return errors.New(
							"inventory tree participant missing",
						)
					}
					participant, err := newNodeSigning(
						owner, digest,
					)
					if err != nil {
						return err
					}
					participants[peerID] = participant
					peerNonces[peerID] = participant.Public
				}
				if err := signing.bindNonces(
					operator, node, digest,
					t.SweepTapscriptRoot, peerNonces,
				); err != nil {

					return err
				}

				// Every participant signs against all other
				// committed public nonces, reproducing the same
				// aggregate session as a multi-party client
				// round.
				partials := make(map[string][]byte)
				for peerID, participant := range participants {
					others := map[string][]byte{
						operatorID: signing.Public,
					}
					for otherID, nonce := range peerNonces {
						if otherID != peerID {
							others[otherID] = nonce
						}
					}
					if err := participant.bindNonces(
						owners[peerID], node, digest,
						t.SweepTapscriptRoot, others,
					); err != nil {

						return err
					}
					partials[peerID] = participant.Partial
				}
				sig, err := signing.combine(
					operator.PubKey(), node, digest,
					t.SweepTapscriptRoot, partials,
				)
				if err != nil {
					return err
				}
				r.Sigs.AggSigs[id] = sig.Serialize()
				return nil
			},
		)
		if err != nil {
			return err
		}

		// Save the complete tree before using the normal commitment
		// finalizer. The publication worker can then recover this
		// refill after a restart.
		if err := s.put(roundKey(r.ID), r); err != nil {
			return err
		}
		_, err = s.SubmitForfeitSigs(
			context.WithValue(ctx, principalKey{}, s.id),
			&roundpb.SubmitForfeitSigRequest{
				RoundId: id[:],
			},
		)
		return err
	})
}

// inventoryFunding identifies the finalized package and its canonical recipient
// outpoint, which can follow a smaller treasury change output.
type inventoryFunding struct {
	Session  string
	Outpoint wire.OutPoint
}

// fundInventoryOutput atomically spends confirmed treasury VTXOs through the
// same OOR validation and signing path as clients. The caller commits the
// operation's session ID in this transaction before any notification escapes.
// amount is in satoshis. Insufficient inventory, invalid policy or failed
// chain validation returns an error that the caller must propagate to roll back
// all staged changes.
func (s *Server) fundInventoryOutput(ctx context.Context, policyRaw []byte,
	amount uint64) (*inventoryFunding, error) {

	// Resolve the destination policy before selecting funds; the requested
	// amount is in satoshis and must form a valid non-dust VTXO.
	policy, err := arkscript.DecodePolicyTemplate(policyRaw)
	if err != nil {
		return nil, err
	}
	script, err := policy.PkScript()
	if err != nil {
		return nil, err
	}
	if amount < uint64(
		s.cfg.MinAmount,
	) {

		return nil, status.Error(
			codes.InvalidArgument, "inventory output below minimum",
		)
	}

	// Select enough value for either an exact payment or valid treasury
	// change; a residual below the minimum cannot become an extra output.
	available, err := s.inventoryCoins()
	if err != nil {
		return nil, err
	}
	var selected []*vtxoRecord
	var total uint64
	for _, coin := range available {
		selected = append(selected, coin)
		total += coin.VTXO.ValueSat
		if total == amount || total >= amount+uint64(s.cfg.MinAmount) {
			break
		}
	}
	if total < amount ||
		total > amount && total-amount < uint64(s.cfg.MinAmount) {

		return nil, status.Error(
			codes.ResourceExhausted,
			"confirmed Ark inventory unavailable",
		)
	}

	// Conserve selected value by returning any excess to the known treasury
	// policy, keeping that change available for subsequent transfers.
	recipients := []oortx.RecipientOutput{
		{
			PkScript: script,
			Value: btcutil.Amount(
				amount,
			),
			VTXOPolicyTemplate: policyRaw,
		},
	}
	if total > amount {
		change, err := s.inventoryPolicy()
		if err != nil {
			return nil, err
		}
		raw, err := change.Encode()
		if err != nil {
			return nil, err
		}
		script, err := change.PkScript()
		if err != nil {
			return nil, err
		}
		recipients = append(recipients, oortx.RecipientOutput{
			PkScript:           script,
			Value:              btcutil.Amount(total - amount),
			VTXOPolicyTemplate: raw,
		})
	}

	// Build owner-signed checkpoints from indexed coins and their saved key
	// derivations, just as an external wallet would prepare an OOR package.
	var checkpoints []*psbt.Packet
	var outputs []oortx.CheckpointOutput
	var descriptors []oorpb.SigningDescriptor
	owners := make(map[chainhash.Hash]*btcec.PrivateKey)
	paths := make(map[chainhash.Hash]*arkscript.SpendPath)
	for _, coin := range selected {
		domain, err := get[string](
			s,
			"inventory-script/"+hex.EncodeToString(coin.VTXO.PkScript),
		)
		if err != nil || domain == nil {
			return nil, errors.New("inventory key missing")
		}
		owner := s.deriveKey(*domain)
		path, _, err := standardPath(coin.Policy)
		if err != nil {
			return nil, err
		}
		rawPath, err := path.Encode()
		if err != nil {
			return nil, err
		}
		leaf := arkscript.LeafTemplate{
			Node: &arkscript.Multisig{
				Keys: []*btcec.PublicKey{
					owner.PubKey(), s.key.PubKey(),
				},
			},
		}
		rawLeaf, err := leaf.Encode()
		if err != nil {
			return nil, err
		}
		op, err := indexedOutpoint(coin.VTXO)
		if err != nil {
			return nil, err
		}
		cp, err := oortx.BuildCheckpointPSBT(
			arkscript.CheckpointPolicy{
				OperatorKey: s.key.PubKey(),
				CSVDelay:    s.cfg.ExitDelay,
			}, oortx.CheckpointInput{
				SpentVTXO: oortx.SpentVTXORef{
					Outpoint: op,
					Output: wire.NewTxOut(
						int64(coin.VTXO.ValueSat),
						coin.VTXO.PkScript,
					),
				},
				OwnerLeafPolicy: rawLeaf,
			},
		)
		if err != nil {
			return nil, err
		}
		output, err := cp.ToCheckpointOutput()
		if err != nil {
			return nil, err
		}
		checkpoints = append(checkpoints, cp.PSBT)
		outputs = append(outputs, output)
		owners[output.Txid] = owner
		paths[output.Txid] = path
		descriptors = append(descriptors, oorpb.SigningDescriptor{
			Outpoint:           op,
			VTXOPolicyTemplate: coin.Policy,
			SpendPath:          rawPath,
			OwnerLeafPolicy:    rawLeaf,
		})
	}

	// The public builder sorts outputs by value and script, and inputs by
	// checkpoint txid. Keep RPC metadata in that output order and bind keys
	// by checkpoint identity rather than the treasury coin selection order.
	recipientIndex, err := oortx.RecipientOutputIndex(
		recipients, recipients[0],
	)
	if err != nil {
		return nil, err
	}
	recipients = oortx.CanonicalRecipientOutputs(recipients)
	ark, err := oortx.BuildArkPSBT(outputs, recipients)
	if err != nil {
		return nil, err
	}

	// Use the operator's validation to derive the exact Ark spend paths
	// before producing the treasury-owner signatures.
	bindings, err := s.validateOOR(
		ark, checkpoints, descriptors, recipients,
	)
	if err != nil {
		return nil, err
	}
	for i, input := range ark.UnsignedTx.TxIn {
		checkpointID := input.PreviousOutPoint.Hash
		if err := signPacketInput(
			ark, i, owners[checkpointID],
			bindings[checkpointID].ArkSpend,
		); err != nil {

			return nil, err
		}
	}
	req, err := oorpb.NewSubmitPackageRequest(
		ark, checkpoints, descriptors, recipients,
	)
	if err != nil {
		return nil, err
	}

	// Run both protocol phases as the treasury mailbox. Normal admission
	// and finalization enforce reservations and build recipient recovery
	// events.
	ctx = context.WithValue(ctx, principalKey{}, s.id)
	resp, err := s.SubmitPackage(ctx, req)
	if err != nil {
		return nil, err
	}
	id, _, signed, err := oorpb.ParseSubmitPackageResponse(resp)
	if err != nil {
		return nil, err
	}
	for _, cp := range signed {
		checkpointID := cp.UnsignedTx.TxHash()
		if err := signPacketInput(
			cp, 0, owners[checkpointID], paths[checkpointID],
		); err != nil {

			return nil, err
		}
	}
	final, err := oorpb.NewFinalizePackageRequest(id, signed)
	if err != nil {
		return nil, err
	}
	if _, err := s.FinalizePackage(ctx, final); err != nil {
		return nil, err
	}
	return &inventoryFunding{
		Session:  id.String(),
		Outpoint: wire.OutPoint{Hash: id, Index: recipientIndex},
	}, nil
}

// spendOwnedVTXO materializes a swap participant's claim or refund through a
// fully signed checkpoint and Ark transaction. The supplied path includes any
// preimage and is checked against the authoritative indexed input.
// The caller must run inside transact and commit the returned session with its
// swap transition. The full indexed value returns to treasury inventory; errors
// must abort the enclosing transition.
func (s *Server) spendOwnedVTXO(ctx context.Context, record *vtxoRecord,
	owner *btcec.PrivateKey, path *arkscript.SpendPath) (string, error) {

	// Carry the selected claim or refund conditions into a checkpoint while
	// retaining operator participation in its subsequent collaborative
	// spend.
	op, err := indexedOutpoint(record.VTXO)
	if err != nil {
		return "", err
	}
	rawPath, err := path.Encode()
	if err != nil {
		return "", err
	}
	leaf := arkscript.LeafTemplate{
		Node: &arkscript.Multisig{
			Keys: []*btcec.PublicKey{
				owner.PubKey(), s.key.PubKey(),
			},
		},
	}
	rawLeaf, err := leaf.Encode()
	if err != nil {
		return "", err
	}
	cp, err := oortx.BuildCheckpointPSBT(
		arkscript.CheckpointPolicy{
			OperatorKey: s.key.PubKey(),
			CSVDelay:    10,
		}, oortx.CheckpointInput{
			SpentVTXO: oortx.SpentVTXORef{
				Outpoint: op,
				Output: wire.NewTxOut(
					int64(record.VTXO.ValueSat),
					record.VTXO.PkScript,
				),
			}, OwnerLeafPolicy: rawLeaf},
	)
	if err != nil {
		return "", err
	}

	// The checkpoint must honor the original claim/refund timelocks before
	// its txid is used as an input to the Ark transaction.
	cp.PSBT.UnsignedTx.TxIn[0].Sequence = path.RequiredSequence
	cp.PSBT.UnsignedTx.LockTime = path.RequiredLockTime
	output, err := cp.ToCheckpointOutput()
	if err != nil {
		return "", err
	}

	// Return the recovered amount to ordinary treasury inventory so a
	// settled swap no longer depends on a conditional policy.
	policy, err := s.inventoryPolicy()
	if err != nil {
		return "", err
	}
	raw, err := policy.Encode()
	if err != nil {
		return "", err
	}
	script, err := policy.PkScript()
	if err != nil {
		return "", err
	}
	recipients := []oortx.RecipientOutput{
		{
			PkScript: script,
			Value: btcutil.Amount(
				record.VTXO.ValueSat,
			),
			VTXOPolicyTemplate: raw,
		},
	}
	ark, err := oortx.BuildArkPSBT([]oortx.CheckpointOutput{
		output,
	}, recipients)
	if err != nil {
		return "", err
	}

	// Bind the original policy and selected spend branch through the same
	// validation and two-phase signing flow used for external clients.
	descriptors := []oorpb.SigningDescriptor{
		{
			Outpoint:           op,
			VTXOPolicyTemplate: record.Policy,
			SpendPath:          rawPath,
			OwnerLeafPolicy:    rawLeaf,
		},
	}
	packets := []*psbt.Packet{cp.PSBT}
	bindings, err := s.validateOOR(ark, packets, descriptors, recipients)
	if err != nil {
		return "", err
	}
	if err := signPacketInput(
		ark, 0, owner, bindings[cp.PSBT.UnsignedTx.TxHash()].ArkSpend,
	); err != nil {

		return "", err
	}
	request, err := oorpb.NewSubmitPackageRequest(
		ark, packets, descriptors, recipients,
	)
	if err != nil {
		return "", err
	}

	// Finish both stages inside the caller's transaction; recording only an
	// operator cosignature would leave the recovery spend incomplete.
	ctx = context.WithValue(ctx, principalKey{}, s.id)
	resp, err := s.SubmitPackage(ctx, request)
	if err != nil {
		return "", err
	}
	id, _, signed, err := oorpb.ParseSubmitPackageResponse(resp)
	if err != nil {
		return "", err
	}
	if err := signPacketInput(signed[0], 0, owner, path); err != nil {
		return "", err
	}
	final, err := oorpb.NewFinalizePackageRequest(id, signed)
	if err != nil {
		return "", err
	}
	if _, err := s.FinalizePackage(ctx, final); err != nil {
		return "", err
	}
	return id.String(), nil
}
