package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcd/chainhash/v2"
	"github.com/btcsuite/btcd/psbt/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/tree"
	oortx "github.com/lightninglabs/wavelength/lib/tx/oor"
	"github.com/lightninglabs/wavelength/lib/tx/psbtutil"
	"github.com/lightninglabs/wavelength/rpc/oorpb"
	"github.com/lightningnetwork/lnd/tlv"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// oorRecord retains the immutable submit transcript and complete finalized
// recovery package. Input locks remain held once co-signatures are exposed.
type oorRecord struct {
	RoundID   string
	Owner     string
	Request   *oorpb.SubmitPackageRequest
	Success   *oorpb.SubmitPackageSuccess
	Final     []*arkrpc.OORSessionPackage
	Inputs    []string
	Ancestors []*arkrpc.OORSessionPackage
	Paths     []*arkrpc.AncestryPath
	Expiry    int32
	Depth     uint32
}

// oorKey identifies a session by its deterministic Ark transaction ID.
func oorKey(id chainhash.Hash) string { return "oor/" + id.String() }

// registerOOR binds generated package RPCs and the public client's TLV receipt.
func (s *Server) registerOOR() {
	oorpb.RegisterOORMailboxServiceMailboxServer(s.router, s)
	s.router.Handle(
		oorpb.ServiceName, oorpb.MethodIncomingAck,
		func() proto.Message { return &anypb.Any{} },
		func(ctx context.Context, message proto.Message) (proto.Message,
			error) {

			ack := message.(*anypb.Any)
			if ack.TypeUrl != "type.lightninglabs.dev/wavelength/oor/SendIncomingAckRequest" {
				return nil, status.Error(
					codes.InvalidArgument,
					"invalid OOR receipt type",
				)
			}
			stream, err := tlv.NewStream()
			if err != nil {
				return nil, err
			}
			fields, err := stream.DecodeWithParsedTypes(
				bytes.NewReader(ack.Value),
			)
			if err != nil {
				return nil, status.Error(
					codes.InvalidArgument,
					"invalid OOR receipt",
				)
			}
			id, err := chainhash.NewHash(fields[1])
			if err != nil {
				return nil, status.Error(
					codes.InvalidArgument,
					"invalid OOR receipt session",
				)
			}
			r, err := get[oorRecord](s, oorKey(*id))
			if err != nil {
				return nil, err
			}
			if r != nil && len(r.Final) > 0 {
				for _, output := range r.Request.RecipientOutputs {
					if _, registered := s.state.Records[registrationKey(principal(ctx), output.PkScript)]; registered {
						return nil, s.put(
							"oor-receipt/"+id.String()+"/"+principal(ctx),
							true,
						)
					}
				}
			}
			return nil, status.Error(
				codes.PermissionDenied,
				"receipt does not match recipient",
			)
		},
	)
}

// SubmitPackage validates and co-signs a real OOR package, retaining its exact
// recovery artifacts and input reservations before returning any signatures.
func (s *Server) SubmitPackage(ctx context.Context,
	req *oorpb.SubmitPackageRequest) (*oorpb.SubmitPackageResponse, error) {

	if req.GetFlowVersion() != 0 {
		return nil, status.Error(
			codes.InvalidArgument, "unsupported OOR flow",
		)
	}
	ark, checkpoints, descriptors, recipients, err := oorpb.ParseSubmitPackageRequest(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	id := ark.UnsignedTx.TxHash()
	old, err := get[oorRecord](s, oorKey(id))
	if err != nil {
		return nil, err
	}
	if old != nil {
		if old.Owner != principal(ctx) ||
			!proto.Equal(old.Request, req) {

			return nil, status.Error(
				codes.AlreadyExists, "OOR session conflict",
			)
		}
		response := &oorpb.SubmitPackageResponse{
			Result: &oorpb.SubmitPackageResponse_Success{
				Success: old.Success,
			},
		}
		return response, s.emit(
			principal(ctx), oorpb.ServiceName,
			oorpb.MethodSubmitPackage, response,
		)
	}
	inputs, err := s.validateOOR(ark, checkpoints, descriptors, recipients)
	if err == nil {
		err = s.validateOORChain(ctx, inputs)
	}
	if err != nil {
		response := oorpb.NewSubmitPackageRejection(
			id, oorpb.OORRejectCode_OOR_REJECT_UNSPECIFIED,
			err.Error(), s.height,
		)
		return response, s.emit(
			principal(ctx), oorpb.ServiceName,
			oorpb.MethodSubmitPackage, response,
		)
	}
	r := &oorRecord{
		Owner: principal(
			ctx,
		),
		Request: proto.Clone(
			req,
		).(*oorpb.SubmitPackageRequest),
	}
	if err := s.oorLineage(r, ark, inputs); err != nil {
		return nil, err
	}
	for i, input := range ark.UnsignedTx.TxIn {
		bound := inputs[input.PreviousOutPoint.Hash]
		if err := signPacketInput(
			ark, i, s.key, bound.ArkSpend,
		); err != nil {

			return nil, status.Error(
				codes.InvalidArgument, err.Error(),
			)
		}
	}
	if _, err := oortx.ValidateSubmitPackageSigned(
		ark, checkpoints,
	); err != nil {

		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	for _, input := range inputs {
		if err := signPacketInput(
			input.Packet, 0, s.key, input.Spend,
		); err != nil {

			return nil, status.Error(
				codes.InvalidArgument, err.Error(),
			)
		}
		outpoint := input.Packet.UnsignedTx.TxIn[0].PreviousOutPoint
		if err := s.put(
			"reserved/"+outpoint.String(), id.String(),
		); err != nil {

			return nil, err
		}
		r.Inputs = append(r.Inputs, outpoint.String())
	}
	response, err := oorpb.NewSubmitPackageResponse(id, ark, checkpoints)
	if err != nil {
		return nil, err
	}
	r.Success = response.GetSuccess()
	if err := s.put(oorKey(id), r); err != nil {
		return nil, err
	}
	return response, s.emit(
		principal(ctx), oorpb.ServiceName, oorpb.MethodSubmitPackage,
		response,
	)
}

// FinalizePackage verifies checkpoint signatures against the original prevouts
// and atomically consumes inputs, creates outputs and queues recipient events.
func (s *Server) FinalizePackage(ctx context.Context,
	req *oorpb.FinalizePackageRequest) (*oorpb.FinalizePackageResponse,
	error) {

	id, checkpoints, err := oorpb.ParseFinalizePackageRequest(req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	r, err := get[oorRecord](s, oorKey(id))
	if err != nil {
		return nil, err
	}
	if r == nil || r.Owner != principal(ctx) {
		return nil, status.Error(
			codes.NotFound, "OOR session not found",
		)
	}
	ark, err := psbtutil.Parse(r.Success.CoSignedArkPsbt)
	if err != nil {
		return nil, err
	}
	previous := make(map[chainhash.Hash]*psbt.Packet)
	for _, raw := range r.Success.CoSignedCheckpointPsbts {
		packet, err := psbtutil.Parse(raw)
		if err != nil {
			return nil, err
		}
		previous[packet.UnsignedTx.TxHash()] = packet
	}
	for _, packet := range checkpoints {
		original := previous[packet.UnsignedTx.TxHash()]
		if original == nil || len(
			packet.Inputs,
		) != 1 || packet.Inputs[0].WitnessUtxo == nil || packet.Inputs[0].WitnessUtxo.Value != original.Inputs[0].WitnessUtxo.Value || !bytes.Equal(
			packet.Inputs[0].WitnessUtxo.PkScript,
			original.Inputs[0].WitnessUtxo.PkScript,
		) {

			return nil, status.Error(
				codes.InvalidArgument,
				"final checkpoint changed",
			)
		}
	}
	if err := oortx.ValidateFinalizePackageSigned(
		ark, checkpoints,
	); err != nil {

		return nil, status.Error(codes.PermissionDenied, err.Error())
	}
	response := oorpb.NewFinalizePackageResponse(id)
	if len(r.Final) > 0 {
		return response, s.emit(
			r.Owner, oorpb.ServiceName, oorpb.MethodFinalizePackage,
			response,
		)
	}
	packageData := &arkrpc.OORSessionPackage{SessionId: id[:], ArkPsbt: r.Success.CoSignedArkPsbt,
		CheckpointPsbts: req.FinalCheckpointPsbts}
	r.Final = []*arkrpc.OORSessionPackage{packageData}
	if err := s.indexOOR(r, id, ark); err != nil {
		return nil, err
	}
	if err := s.put(oorKey(id), r); err != nil {
		return nil, err
	}
	return response, s.emit(
		r.Owner, oorpb.ServiceName, oorpb.MethodFinalizePackage,
		response,
	)
}

// oorLineage unions signed tree fragments and orders complete ancestor packages
// before descendants, retaining all roots for cross-commitment transfers.
func (s *Server) oorLineage(r *oorRecord, ark *psbt.Packet,
	inputs map[chainhash.Hash]*oorInput) error {

	paths := make(map[string]*arkrpc.AncestryPath)
	packages := make(map[string]bool)
	for i, input := range ark.UnsignedTx.TxIn {
		v := inputs[input.PreviousOutPoint.Hash].Record.VTXO
		if r.RoundID == "" {
			r.RoundID = v.RoundId
		}
		if r.Expiry == 0 || v.BatchExpiryHeight < r.Expiry {
			r.Expiry = v.BatchExpiryHeight
		}
		r.Depth = max(r.Depth, v.ChainDepth+1)
		if r.Depth > 32 {
			return errors.New(
				"OOR lineage exceeds regtest depth limit",
			)
		}
		if len(v.OorArkPsbt) > 0 {
			parentID, err := chainhash.NewHash(v.Outpoint.Txid)
			if err != nil {
				return err
			}
			parent, err := get[oorRecord](s, oorKey(*parentID))
			if err != nil || parent == nil ||
				len(parent.Final) == 0 {

				return errors.New(
					"missing finalized OOR ancestor",
				)
			}
			for _, pkg := range append(
				parent.Ancestors, parent.Final...,
			) {

				if packages[string(pkg.SessionId)] {
					continue
				}
				packages[string(pkg.SessionId)] = true
				r.Ancestors = append(r.Ancestors, pkg)
			}
		}
		for _, path := range v.AncestryPaths {
			key := string(path.CommitmentTxid)
			current := paths[key]
			if current == nil {
				current = proto.Clone(
					path,
				).(*arkrpc.AncestryPath)
				current.InputIndices = nil
				paths[key] = current
			} else if err := mergeAncestry(
				current, path,
			); err != nil {

				return err
			}
			current.InputIndices = append(
				current.InputIndices, uint32(i),
			)
		}
	}
	for _, path := range paths {
		r.Paths = append(r.Paths, path)
	}
	sort.Slice(r.Paths, func(i, j int) bool {
		return bytes.Compare(
			r.Paths[i].CommitmentTxid, r.Paths[j].CommitmentTxid,
		) < 0
	})
	return nil
}

// mergeAncestry combines branches with the same signed commitment root.
func mergeAncestry(destination, source *arkrpc.AncestryPath) error {
	dst, err := arkrpc.AncestryPathToTree(destination)
	if err != nil {
		return err
	}
	src, err := arkrpc.AncestryPathToTree(source)
	if err != nil {
		return err
	}
	if dst.BatchOutpoint != src.BatchOutpoint {
		return errors.New("ancestry commitment roots differ")
	}
	if err := mergeNodes(dst.Root, src.Root); err != nil {
		return err
	}
	merged, err := arkrpc.AncestryPathFromTree(
		dst, dst.BatchOutpoint.Hash, destination.InputIndices,
	)
	if err != nil {
		return err
	}
	destination.TreePath, destination.TreeDepth = merged.TreePath, merged.TreeDepth
	return nil
}

// mergeNodes adds signed branches without accepting inconsistent transactions.
func mergeNodes(destination, source *tree.Node) error {
	dst, err := destination.ToSignedTx()
	if err != nil {
		return err
	}
	src, err := source.ToSignedTx()
	if err != nil {
		return err
	}
	if dst.WitnessHash() != src.WitnessHash() {
		return errors.New("inconsistent signed ancestry")
	}
	for index, child := range source.Children {
		if existing := destination.Children[index]; existing != nil {
			if err := mergeNodes(existing, child); err != nil {
				return err
			}
		} else {
			if destination.Children == nil {
				destination.Children = make(map[uint32]*tree.Node)
			}
			destination.Children[index] = child
		}
	}
	return nil
}

// indexOOR records spent inputs and complete signed output recovery metadata.
func (s *Server) indexOOR(r *oorRecord, id chainhash.Hash,
	ark *psbt.Packet) error {

	for _, input := range r.Inputs {
		record, err := get[vtxoRecord](s, "vtxo/"+input)
		if err != nil || record == nil {
			return errors.New("missing consumed OOR input")
		}
		record.VTXO.Status = arkrpc.VTXOStatus_VTXO_STATUS_SPENT
		record.VTXO.SpentByTxid = id[:]
		if err := s.recordVTXO(
			"vtxo/"+input, record,
			arkrpc.VTXOOrigin_VTXO_ORIGIN_OOR,
		); err != nil {

			return err
		}
	}
	tx, err := signedPacket(ark)
	if err != nil {
		return err
	}
	var raw bytes.Buffer
	if err := tx.Serialize(&raw); err != nil {
		return err
	}
	for i, recipient := range r.Request.RecipientOutputs {
		outpoint := wire.OutPoint{Hash: id, Index: uint32(i)}
		v := &arkrpc.VTXO{Outpoint: &arkrpc.OutPoint{
			Txid: id[:],
			Vout: uint32(i),
		},
			ValueSat: uint64(
				recipient.ValueSat,
			), PkScript: recipient.PkScript,
			Status: arkrpc.VTXOStatus_VTXO_STATUS_LIVE, CreatedHeight: int32(s.height), RoundId: r.RoundID,
			BatchExpiryHeight: r.Expiry, RelativeExpiry: s.cfg.ExitDelay,
			LeafTx: raw.Bytes(), OorArkPsbt: r.Final[0].ArkPsbt,
			OorFinalCheckpointPsbts: r.Final[0].CheckpointPsbts,
			ChainDepth:              r.Depth, AncestryPaths: r.Paths,
			OperatorPubkey: s.key.PubKey().SerializeCompressed(), ConstructionVersion: 1}
		if len(r.Paths) > 0 {
			v.CommitmentTxid = r.Paths[0].CommitmentTxid
			v.BatchOutputIndex = r.Paths[0].TreePath.BatchOutpoint.Vout
		}
		record := &vtxoRecord{
			VTXO:   v,
			Policy: recipient.VtxoPolicyTemplate,
		}
		if err := s.recordVTXO(
			"vtxo/"+outpoint.String(), record,
			arkrpc.VTXOOrigin_VTXO_ORIGIN_OOR,
		); err != nil {

			return err
		}
		event := &arkrpc.OORRecipientEvent{RecipientPkScript: v.PkScript,
			EventId: record.EventID, SessionId: id[:], OutputIndex: uint32(i), Value: v.ValueSat,
			ArkPsbt: r.Final[0].ArkPsbt, CheckpointPsbts: r.Final[0].CheckpointPsbts,
			AncestorPackages: r.Ancestors, VtxoPolicyTemplate: record.Policy}
		if err := s.put(
			fmt.Sprintf("oor-event/%020d", event.EventId), event,
		); err != nil {

			return err
		}
		if err := s.notifyOOR(event); err != nil {
			return err
		}
	}
	return nil
}

// notifyOOR sends a durable wake-up hint; proof-gated queries carry the
// complete package and metadata needed by the receiving wallet.
func (s *Server) notifyOOR(event *arkrpc.OORRecipientEvent) error {
	notification := &arkrpc.IncomingOOREvent{
		RecipientPkScript: event.RecipientPkScript,
		RecipientEventId:  event.EventId, SessionId: event.SessionId,
		OutputIndex: event.OutputIndex, Value: event.Value,
	}
	for key := range s.state.Records {
		if !strings.HasPrefix(key, "script/") {
			continue
		}
		subscription, err := get[registeredScript](s, key)
		if err != nil {
			return err
		}
		if !bytes.Equal(
			subscription.Script.PkScript, event.RecipientPkScript,
		) || (subscription.Script.ExpiresAtUnixS != 0 &&
			subscription.Script.ExpiresAtUnixS <= uint64(
				s.cfg.Clock.Now().Unix(),
			)) {

			continue
		}
		if err := s.emit(
			subscription.Owner, "arkrpc.ArkService", "IncomingOOR",
			notification,
		); err != nil {

			return err
		}
	}
	return nil
}
