package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	"github.com/lightninglabs/wavelength/rpc/roundpb"
	"github.com/lightningnetwork/lnd/tlv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// indexerProofServerID is the literal domain pinned by the public waved
	// client.
	indexerProofServerID = "lumosd"
)

// registeredScript keeps routing separate from independently proven ownership.
type registeredScript struct {
	Owner  string
	Script *arkrpc.RegisteredReceiveScript
}

// vtxoRecord preserves the policy alongside the wallet-facing lineage record.
type vtxoRecord struct {
	VTXO    *arkrpc.VTXO
	Policy  []byte
	EventID uint64
}

// indexEvent binds an event to its script for proof-gated catch-up queries.
type indexEvent struct {
	Script []byte
	Event  *arkrpc.VTXOEvent
}

// verifyScriptProof validates the public client's TLV proof and resolves the
// signing key's relationship to the requested script. Scope proofs deliberately
// bind a participant, so the relationship is checked for every queried script.
func (s *Server) verifyScriptProof(ctx context.Context, script []byte,
	proof *arkrpc.TaprootSchnorrProof, purpose string) error {

	if principal(ctx) == "" || proof == nil || len(proof.Message) > 4096 ||
		!txscript.IsPayToTaproot(script) {

		return status.Error(
			codes.InvalidArgument,
			"script and bounded Schnorr proof required",
		)
	}
	stream, err := tlv.NewStream()
	if err != nil {
		return err
	}
	fields, err := stream.DecodeWithParsedTypes(bytes.NewReader(
		proof.Message,
	))
	if err != nil {
		return status.Error(
			codes.InvalidArgument, "malformed indexer proof",
		)
	}
	wantType := "script_scope"
	if purpose == "register_receive_script" ||
		purpose == "unregister_receive_script" {

		wantType = "receive_script_registration"
	}
	if string(fields[1]) != wantType ||
		!bytes.Equal(fields[2], []byte{
			0, 0, 0, 0,
		}) ||
		string(fields[3]) != indexerProofServerID ||
		string(fields[4]) != principal(ctx) ||
		string(fields[9]) != purpose || len(fields[8]) != 32 ||
		len(fields[6]) != 8 || len(fields[7]) != 8 {

		return status.Error(
			codes.PermissionDenied, "indexer proof scope mismatch",
		)
	}
	now := uint64(s.cfg.Clock.Now().Unix())
	issued, expires := binary.BigEndian.Uint64(
		fields[6],
	), binary.BigEndian.Uint64(fields[7])
	if issued > now+30 || expires <= now || expires <= issued ||
		expires-issued > 600 {

		return status.Error(
			codes.PermissionDenied,
			"indexer proof expired or outside validity window",
		)
	}
	if len(fields[5]) > 0 && !bytes.Equal(fields[5], script) {
		return status.Error(
			codes.PermissionDenied, "indexer proof script mismatch",
		)
	}
	var key *btcec.PublicKey
	identity := fields[11]
	if len(identity) == 0 {
		identity = fields[10]
	}
	if len(identity) > 0 {
		key, err = btcec.ParsePubKey(identity)
		if err != nil {
			return status.Error(
				codes.InvalidArgument, "invalid proof signer",
			)
		}
		if !s.participates(script, key) {
			return status.Error(
				codes.PermissionDenied,
				"signer does not control script",
			)
		}
	} else {
		if !bytes.Equal(fields[5], script) {
			return status.Error(
				codes.PermissionDenied,
				"proof does not bind script",
			)
		}
		key, err = schnorr.ParsePubKey(script[2:])
		if err != nil {
			return status.Error(
				codes.InvalidArgument, "invalid output key",
			)
		}
	}
	sig, err := schnorr.ParseSignature(proof.Sig64)
	if err != nil {
		return status.Error(
			codes.InvalidArgument, "invalid proof signature",
		)
	}
	digest := chainhash.TaggedHash(
		[]byte("wavelength/indexer/v1"), proof.Message,
	)
	if !sig.Verify(digest[:], key) {
		return status.Error(
			codes.PermissionDenied, "invalid script proof",
		)
	}
	return nil
}

// participates checks standard receive scripts or a registered custom policy.
func (s *Server) participates(script []byte, key *btcec.PublicKey) bool {
	if len(script) != 34 {
		return false
	}
	standard, err := arkscript.StandardVTXOTemplate(
		key, s.key.PubKey(), s.cfg.ExitDelay,
	)
	if err == nil {
		computed, err := standard.PkScript()
		if err == nil && bytes.Equal(computed, script) {
			return true
		}
	}
	if bytes.Equal(schnorr.SerializePubKey(key), script[2:]) {
		return true
	}
	if hasKey([]*btcec.PublicKey{s.key.PubKey()}, key) {
		return false
	}
	known, err := get[[]byte](s, "known-policy/"+hex.EncodeToString(script))
	if err == nil && known != nil {
		policy, err := arkscript.DecodePolicyTemplate(*known)
		if err == nil && hasKey(policy.ParticipantKeys(), key) {
			return true
		}
	}
	for recordKey := range s.state.Records {
		if !strings.HasPrefix(recordKey, "vtxo/") {
			continue
		}
		record, err := get[vtxoRecord](s, recordKey)
		if err != nil || !bytes.Equal(record.VTXO.PkScript, script) {
			continue
		}
		policy, err := arkscript.DecodePolicyTemplate(record.Policy)
		if err == nil && hasKey(policy.ParticipantKeys(), key) {
			return true
		}
	}
	return false
}

// registrationKey identifies one principal's routing subscription.
func registrationKey(owner string, script []byte) string {
	return "script/" + owner + "/" + hex.EncodeToString(script)
}

// RegisterReceiveScript stores a proven routing subscription idempotently.
func (s *Server) RegisterReceiveScript(ctx context.Context, req *arkrpc.RegisterReceiveScriptRequest) (*arkrpc.RegisterReceiveScriptResponse, error) {
	if err := s.verifyScriptProof(
		ctx, req.GetPkScript(), req.GetTaprootSchnorr(),
		"register_receive_script",
	); err != nil {

		return nil, err
	}
	if len(
		req.Label,
	) > 256 {

		return nil, status.Error(
			codes.InvalidArgument, "label too long",
		)
	}
	if req.ExpiresAtUnixS != 0 &&
		req.ExpiresAtUnixS <= uint64(s.cfg.Clock.Now().Unix()) {

		return nil, status.Error(
			codes.InvalidArgument, "registration expired",
		)
	}
	err := s.put(
		registrationKey(principal(ctx), req.PkScript),
		&registeredScript{
			Owner: principal(
				ctx,
			), Script: &arkrpc.RegisteredReceiveScript{
				PkScript:       req.PkScript,
				ExpiresAtUnixS: req.ExpiresAtUnixS,
				Label:          req.Label,
			},
		},
	)
	return &arkrpc.RegisterReceiveScriptResponse{}, err
}

// ListMyReceiveScripts lists active subscriptions for the authenticated
// mailbox.
func (s *Server) ListMyReceiveScripts(ctx context.Context, _ *arkrpc.ListMyReceiveScriptsRequest) (*arkrpc.ListMyReceiveScriptsResponse, error) {
	resp := &arkrpc.ListMyReceiveScriptsResponse{}
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "script/"+principal(ctx)+"/") {
			continue
		}
		r, err := get[registeredScript](s, key)
		if err != nil {
			return nil, err
		}
		if r.Script.ExpiresAtUnixS == 0 || r.Script.ExpiresAtUnixS > uint64(s.cfg.Clock.Now().Unix()) {
			resp.Scripts = append(resp.Scripts, r.Script)
		}
	}
	sort.Slice(resp.Scripts, func(i, j int) bool {
		return bytes.Compare(
			resp.Scripts[i].PkScript, resp.Scripts[j].PkScript,
		) < 0
	})
	return resp, nil
}

// UnregisterReceiveScript removes only the caller's proven routing
// subscription.
func (s *Server) UnregisterReceiveScript(ctx context.Context, req *arkrpc.UnregisterReceiveScriptRequest) (*arkrpc.UnregisterReceiveScriptResponse, error) {
	if err := s.verifyScriptProof(
		ctx, req.GetPkScript(), req.GetTaprootSchnorr(),
		"unregister_receive_script",
	); err != nil {

		return nil, err
	}
	delete(s.state.Records, registrationKey(principal(ctx), req.PkScript))
	return &arkrpc.UnregisterReceiveScriptResponse{}, nil
}

// scriptScopes validates a bounded set of independently authorized scripts.
func (s *Server) scriptScopes(ctx context.Context, scopes []*arkrpc.ScriptScope,
	purpose string) (map[string]bool, error) {

	if len(
		scopes,
	) == 0 || len(
		scopes,
	) > 1000 {

		return nil, status.Error(
			codes.InvalidArgument, "invalid script count",
		)
	}
	allowed := make(map[string]bool)
	for _, scope := range scopes {
		if err := s.verifyScriptProof(
			ctx, scope.GetPkScript(), scope.GetTaprootSchnorr(),
			purpose,
		); err != nil {

			return nil, err
		}
		allowed[hex.EncodeToString(scope.PkScript)] = true
	}
	return allowed, nil
}

// queryLimit applies the indexer's bounded default page size.
func queryLimit(limit uint32) int {
	if limit == 0 {
		return 100
	}
	return int(min(limit, 1000))
}

// ListVTXOsByScripts returns authoritative, paginated lineage and spend status.
func (s *Server) ListVTXOsByScripts(ctx context.Context, req *arkrpc.ListVTXOsByScriptsRequest) (*arkrpc.ListVTXOsByScriptsResponse, error) {
	allowed, err := s.scriptScopes(
		ctx, req.GetScripts(), "list_vtxos_by_scripts",
	)
	if err != nil {
		return nil, err
	}
	var scripts []string
	for script := range allowed {
		scripts = append(scripts, script)
	}
	sort.Strings(scripts)
	filters := slices.Clone(req.StatusFilter)
	slices.Sort(filters)
	binding, err := json.Marshal([]any{principal(ctx), scripts, filters})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(binding)
	after := ""
	if len(req.Cursor) > 0 {
		if len(req.Cursor) < 32 ||
			!bytes.Equal(req.Cursor[:32], hash[:]) {

			return nil, status.Error(
				codes.InvalidArgument, "cursor query mismatch",
			)
		}
		after = string(req.Cursor[32:])
	}
	var keys []string
	for key := range s.state.Records {
		if strings.HasPrefix(
			key, "vtxo/",
		) && key > after {

			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	resp := &arkrpc.ListVTXOsByScriptsResponse{}
	last := ""
	for _, key := range keys {
		r, err := get[vtxoRecord](s, key)
		if err != nil {
			return nil, err
		}
		if !allowed[hex.EncodeToString(
			r.VTXO.PkScript,
		)] || len(
			filters,
		) > 0 && !slices.Contains(filters, r.VTXO.Status) {

			continue
		}
		if len(resp.Vtxos) == queryLimit(req.Limit) {
			resp.NextCursor = append(hash[:], []byte(last)...)
			break
		}
		resp.Vtxos = append(resp.Vtxos, r.VTXO)
		last = key
	}
	return resp, nil
}

// ListVTXOEventsByScripts returns monotonically ordered, proof-scoped changes.
func (s *Server) ListVTXOEventsByScripts(ctx context.Context, req *arkrpc.ListVTXOEventsByScriptsRequest) (*arkrpc.ListVTXOEventsByScriptsResponse, error) {
	allowed, err := s.scriptScopes(
		ctx, req.GetScripts(), "list_vtxo_events_by_scripts",
	)
	if err != nil {
		return nil, err
	}
	resp := &arkrpc.ListVTXOEventsByScriptsResponse{
		NextCursor: req.AfterEventId,
	}
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "vtxo-event/") {
			continue
		}
		e, err := get[indexEvent](s, key)
		if err != nil {
			return nil, err
		}
		if e.Event.EventId > req.AfterEventId &&
			allowed[hex.EncodeToString(e.Script)] {

			resp.Events = append(resp.Events, e.Event)
		}
	}
	sort.Slice(resp.Events, func(i, j int) bool {
		return resp.Events[i].EventId < resp.Events[j].EventId
	})
	resp.Events = resp.Events[:min(len(resp.Events), queryLimit(req.Limit))]
	if len(
		resp.Events,
	) > 0 {

		resp.NextCursor = resp.Events[len(
			resp.Events,
		)-1].EventId
	}
	return resp, nil
}

// GetSubtreeByScripts returns each matching VTXO's complete signed ancestry.
func (s *Server) GetSubtreeByScripts(ctx context.Context, req *arkrpc.GetSubtreeByScriptsRequest) (*arkrpc.GetSubtreeByScriptsResponse, error) {
	allowed, err := s.scriptScopes(
		ctx, req.GetScripts(), "get_subtree_by_scripts",
	)
	if err != nil {
		return nil, err
	}
	resp := &arkrpc.GetSubtreeByScriptsResponse{}
	seen := make(map[string]bool)
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "vtxo/") {
			continue
		}
		r, err := get[vtxoRecord](s, key)
		if err != nil {
			return nil, err
		}
		if !allowed[hex.EncodeToString(r.VTXO.PkScript)] {
			continue
		}
		resp.Vtxos = append(resp.Vtxos, r.VTXO)
		if !req.IncludeInternalNodes {
			continue
		}
		for _, ancestry := range r.VTXO.AncestryPaths {
			t, err := arkrpc.AncestryPathToTree(ancestry)
			if err != nil {
				return nil, err
			}
			for node := range t.Root.NodesIter() {
				tx, err := node.ToSignedTx()
				if err != nil {
					return nil, err
				}
				hash := tx.TxHash()
				if seen[hash.String()] {
					continue
				}
				seen[hash.String()] = true
				var raw bytes.Buffer
				if err := tx.Serialize(&raw); err != nil {
					return nil, err
				}
				resp.Nodes = append(
					resp.Nodes, &arkrpc.TreeNode{
						Txid: hash[:],
						Input: &arkrpc.OutPoint{
							Txid: node.Input.Hash[:],
							Vout: node.Input.Index,
						},
						NumOutputs: uint32(len(
							tx.TxOut,
						)),
						RawTx: raw.Bytes(),
					},
				)
				for index, child := range node.Children {
					childID, err := child.TXID()
					if err != nil {
						return nil, err
					}
					resp.Edges = append(
						resp.Edges, &arkrpc.TreeEdge{
							ParentTxid:        hash[:],
							ParentOutputIndex: index,
							ChildTxid:         childID[:],
						},
					)
				}
			}
		}
	}
	return resp, nil
}

// ListOORRecipientEventsByScript validates offline receive access before
// lookup.
func (s *Server) ListOORRecipientEventsByScript(ctx context.Context, req *arkrpc.ListOORRecipientEventsByScriptRequest) (*arkrpc.ListOORRecipientEventsByScriptResponse, error) {
	if err := s.verifyScriptProof(
		ctx, req.GetPkScript(), req.GetTaprootSchnorr(),
		"list_oor_recipient_events_by_script",
	); err != nil {

		return nil, err
	}
	response := &arkrpc.ListOORRecipientEventsByScriptResponse{
		NextCursor: req.AfterEventId,
	}
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "oor-event/") {
			continue
		}
		event, err := get[arkrpc.OORRecipientEvent](s, key)
		if err != nil {
			return nil, err
		}
		if event.EventId > req.AfterEventId &&
			bytes.Equal(event.RecipientPkScript, req.PkScript) {

			response.Events = append(response.Events, event)
		}
	}
	sort.Slice(response.Events, func(i, j int) bool {
		return response.Events[i].EventId < response.Events[j].EventId
	})
	response.Events = response.Events[:min(len(response.Events), queryLimit(
		req.Limit,
	))]
	if len(response.Events) > 0 {
		response.NextCursor = response.Events[len(
			response.Events,
		)-1].EventId
	}
	return response, nil
}

// GetOORSessionByTxid requires script ownership even for absent packages.
func (s *Server) GetOORSessionByTxid(ctx context.Context, req *arkrpc.GetOORSessionByTxidRequest) (*arkrpc.GetOORSessionByTxidResponse, error) {
	if _, err := s.scriptScopes(ctx, []*arkrpc.ScriptScope{
		req.GetScript(),
	}, "get_oor_session_by_txid"); err != nil {

		return nil, err
	}
	id, err := chainhash.NewHash(req.SessionTxid)
	if err != nil {
		return nil, status.Error(
			codes.InvalidArgument, "invalid session ID",
		)
	}
	r, err := get[oorRecord](s, oorKey(*id))
	if err != nil {
		return nil, err
	}
	if r != nil && len(r.Final) > 0 {
		for _, input := range r.Inputs {
			record, err := get[vtxoRecord](s, "vtxo/"+input)
			if err != nil {
				return nil, err
			}
			if record != nil && bytes.Equal(
				record.VTXO.PkScript, req.Script.PkScript,
			) {

				return &arkrpc.GetOORSessionByTxidResponse{
					ArkPsbt:         r.Final[0].ArkPsbt,
					CheckpointPsbts: r.Final[0].CheckpointPsbts,
				}, nil
			}
		}
		for _, recipient := range r.Request.RecipientOutputs {
			if bytes.Equal(
				recipient.PkScript, req.Script.PkScript,
			) {

				return &arkrpc.GetOORSessionByTxidResponse{
					ArkPsbt:         r.Final[0].ArkPsbt,
					CheckpointPsbts: r.Final[0].CheckpointPsbts,
				}, nil
			}
		}
	}
	return nil, status.Error(codes.NotFound, "OOR session not found")
}

// indexRound materializes signed leaf VTXOs after their commitment confirms.
func (s *Server) indexRound(r *roundRecord) error {
	if r.ConfirmedHeight == 0 ||
		(len(r.Request.VtxoRequests) > 0 && r.Sigs == nil) {

		return errors.New("round is not confirmed and signed")
	}
	for _, input := range r.Request.ForfeitRequests {
		outpoint, err := roundpb.OutpointFromProto(input.VtxoOutpoint)
		if err != nil {
			return err
		}
		record, err := get[vtxoRecord](s, "vtxo/"+outpoint.String())
		if err != nil {
			return err
		}
		if record == nil {
			return errors.New("missing forfeited input")
		}
		record.VTXO.Status = arkrpc.VTXOStatus_VTXO_STATUS_FORFEITED
		if err := s.recordVTXO(
			"vtxo/"+outpoint.String(), record,
			arkrpc.VTXOOrigin_VTXO_ORIGIN_IN_ROUND,
		); err != nil {

			return err
		}
	}
	for index, encoded := range r.Batch.VtxoTreePaths {
		t, err := roundpb.TreeFromProto(encoded)
		if err != nil {
			return err
		}
		for node := range t.Root.NodesIter() {
			id, err := node.TXID()
			if err != nil {
				return err
			}
			sig, err := schnorr.ParseSignature(
				r.Sigs.AggSigs[roundpb.TxIDToHex(id)],
			)
			if err != nil {
				return err
			}
			node.AddSignature(sig)
		}
		if err := t.VerifySigned(); err != nil {
			return err
		}
		for i, req := range r.Request.VtxoRequests {
			key, err := btcec.ParsePubKey(req.SigningKey)
			if err != nil {
				return err
			}
			leaf := t.Root.GetLeafForCoSigner(key)
			if leaf == nil {
				return errors.New(
					"VTXO missing from signed tree",
				)
			}
			op, err := leaf.GetNonAnchorOutpoint()
			if err != nil {
				return err
			}
			path, err := t.ExtractPathForCoSigners(key)
			if err != nil {
				return err
			}
			ancestry, err := arkrpc.AncestryPathFromTree(
				path, t.BatchOutpoint.Hash, nil,
			)
			if err != nil {
				return err
			}
			ancestry.CommitmentHeight = int32(r.ConfirmedHeight)
			tx, err := leaf.ToSignedTx()
			if err != nil {
				return err
			}
			var raw bytes.Buffer
			if err := tx.Serialize(&raw); err != nil {
				return err
			}
			v := &arkrpc.VTXO{Outpoint: &arkrpc.OutPoint{
				Txid: op.Hash[:],
				Vout: op.Index,
			},
				ValueSat: uint64(
					r.Quote.VtxoQuotes[i].AmountSat,
				), PkScript: r.Quote.VtxoQuotes[i].PkScript,
				Status: arkrpc.VTXOStatus_VTXO_STATUS_LIVE, RoundId: r.ID, CommitmentTxid: t.BatchOutpoint.Hash[:],
				BatchOutputIndex: uint32(
					index,
				), CreatedHeight: int32(r.ConfirmedHeight),
				BatchExpiryHeight: int32(
					r.ConfirmedHeight + s.cfg.BatchLifetime,
				), RelativeExpiry: s.cfg.ExitDelay,
				LeafTx: raw.Bytes(), AncestryPaths: []*arkrpc.AncestryPath{
					ancestry,
				},
				OperatorPubkey: s.key.PubKey().SerializeCompressed(), ConstructionVersion: 1}
			old, err := get[vtxoRecord](s, "vtxo/"+op.String())
			if err != nil {
				return err
			}
			if old != nil && (old.VTXO.Status == arkrpc.VTXOStatus_VTXO_STATUS_SPENT || old.VTXO.Status == arkrpc.VTXOStatus_VTXO_STATUS_FORFEITED) {
				v.Status = old.VTXO.Status
				v.SpentByTxid = old.VTXO.SpentByTxid
			}
			if err := s.recordVTXO("vtxo/"+op.String(), &vtxoRecord{
				VTXO:   v,
				Policy: req.PolicyTemplate,
			}, arkrpc.VTXOOrigin_VTXO_ORIGIN_IN_ROUND); err != nil {

				return err
			}
		}
	}
	return s.reconcileRefreshedSwaps(r)
}

// recordVTXO persists a lineage change and its catch-up event together, then
// schedules notifications for every active subscription to the output script.
// Reindexing unchanged state preserves the original event sequence.
func (s *Server) recordVTXO(key string, record *vtxoRecord,
	origin arkrpc.VTXOOrigin) error {

	old, err := get[vtxoRecord](s, key)
	if err != nil {
		return err
	}
	v := record.VTXO
	eventType := arkrpc.VTXOEventType_VTXO_EVENT_TYPE_CREATED
	if old != nil {
		record.EventID = old.EventID
		if old.VTXO.Status == v.Status &&
			old.VTXO.CreatedHeight == v.CreatedHeight &&
			old.VTXO.BatchExpiryHeight == v.BatchExpiryHeight {

			return s.put(key, record)
		}
		eventType = arkrpc.VTXOEventType_VTXO_EVENT_TYPE_STATUS_CHANGED
	}
	counter, err := get[uint64](s, "index-event-counter")
	if err != nil {
		return err
	}
	id := uint64(1)
	if counter != nil {
		id += *counter
	}
	if err := s.put("index-event-counter", id); err != nil {
		return err
	}
	record.EventID = id
	if err := s.put(key, record); err != nil {
		return err
	}
	event := &arkrpc.VTXOEvent{
		EventId: id, Type: eventType, Outpoint: v.Outpoint,
		Status: v.Status, CreatedAtUnixMs: s.cfg.Clock.Now().UnixMilli(),
	}
	if err := s.put(fmt.Sprintf("vtxo-event/%020d", id), &indexEvent{
		Script: v.PkScript, Event: event,
	}); err != nil {

		return err
	}
	notification := &arkrpc.IncomingVTXOEvent{
		EventId: id, Type: eventType, Outpoint: v.Outpoint,
		Status: v.Status, PkScript: v.PkScript, ValueSat: v.ValueSat,
		RoundId: v.RoundId, BatchExpiryHeight: v.BatchExpiryHeight,
		RelativeExpiry: v.RelativeExpiry, Origin: origin,
		CommitmentTxid: v.CommitmentTxid,
	}
	for subscriptionKey := range s.state.Records {
		if !strings.HasPrefix(subscriptionKey, "script/") {
			continue
		}
		subscription, err := get[registeredScript](s, subscriptionKey)
		if err != nil {
			return err
		}
		script := subscription.Script
		if !bytes.Equal(
			script.PkScript, v.PkScript,
		) || (script.ExpiresAtUnixS != 0 && script.ExpiresAtUnixS <=
			uint64(s.cfg.Clock.Now().Unix())) {

			continue
		}
		if err := s.emit(
			subscription.Owner, "arkrpc.ArkService", "IncomingVTXO",
			notification,
		); err != nil {

			return err
		}
	}
	return nil
}
