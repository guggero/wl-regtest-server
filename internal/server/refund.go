package server

import (
	"bytes"
	"context"
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/lightninglabs/wavelength/arkrpc"
	"github.com/lightninglabs/wavelength/lib/arkscript"
	oortx "github.com/lightninglabs/wavelength/lib/tx/oor"
	"github.com/lightninglabs/wavelength/lib/tx/psbtutil"
	"github.com/lightninglabs/wavelength/swaprpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthorizeInSwapRefund signs only the sender's canonical refund checkpoint,
// after a terminal Lightning failure or expiry before payment initiation.
func (s *Server) AuthorizeInSwapRefund(ctx context.Context, req *swaprpc.AuthorizeInSwapRefundRequest) (*swaprpc.AuthorizeInSwapRefundResponse, error) {
	var response *swaprpc.AuthorizeInSwapRefundResponse
	err := s.transact(ctx, func() error {
		if len(
			req.PaymentHash,
		) != 32 {

			return status.Error(
				codes.InvalidArgument, "payment hash required",
			)
		}
		id := hex.EncodeToString(req.PaymentHash)
		r, err := get[inSwap](s, "in-swap/"+id)
		if err != nil {
			return err
		}
		if r == nil || r.Phase != "failed" || len(r.Preimage) > 0 ||
			r.InArk {

			return status.Error(
				codes.FailedPrecondition,
				"Lightning payment has not terminally failed",
			)
		}

		// An expired offer can receive the finalization of a package
		// signed before expiry. Bind its refund to the authoritative
		// policy and amount before remembering that late outpoint.
		if r.Outpoint == "" {
			coin, err := get[vtxoRecord](
				s, "vtxo/"+req.VhtlcOutpoint,
			)
			if err != nil {
				return err
			}
			if coin == nil || !bytes.Equal(coin.Policy, r.Policy) ||
				coin.VTXO.ValueSat != r.Response.AmountSat {

				return status.Error(
					codes.InvalidArgument,
					"unknown late funding",
				)
			}
			r.Outpoint = req.VhtlcOutpoint
			if err := s.put("in-swap/"+id, r); err != nil {
				return err
			}
		}
		if req.VhtlcOutpoint != r.Outpoint ||
			req.VhtlcAmountSat != r.Response.AmountSat ||
			!bytes.Equal(req.VhtlcPolicyTemplate, r.Policy) {

			return status.Error(
				codes.InvalidArgument,
				"refund does not match funded swap",
			)
		}
		coin, err := get[vtxoRecord](s, "vtxo/"+r.Outpoint)
		if err != nil {
			return err
		}
		if coin == nil ||
			coin.VTXO.Status != arkrpc.VTXOStatus_VTXO_STATUS_LIVE {

			return status.Error(
				codes.FailedPrecondition,
				"refund input not live",
			)
		}
		sender, err := btcec.ParsePubKey(r.Request.ClientVhtlcPubkey)
		if err != nil {
			return err
		}
		receiver := s.deriveKey("swap-receiver/" + id)
		policy, err := s.swapPolicy(
			sender, receiver.PubKey(), r.Response.PaymentHash,
			r.Response.VhtlcConfig,
		)
		if err != nil {
			return err
		}
		path, err := policy.RefundPath()
		if err != nil {
			return err
		}
		rawPath, err := path.Encode()
		if err != nil {
			return err
		}
		if !bytes.Equal(rawPath, req.RefundSpendPath) {
			return status.Error(
				codes.InvalidArgument,
				"wrong refund spend path",
			)
		}
		packet, err := psbtutil.Parse(req.CheckpointPsbt)
		if err != nil {
			return status.Error(
				codes.InvalidArgument,
				"invalid refund checkpoint",
			)
		}
		op, err := indexedOutpoint(coin.VTXO)
		if err != nil {
			return err
		}
		leaf := arkscript.LeafTemplate{
			Node: &arkscript.Multisig{
				Keys: []*btcec.PublicKey{
					sender, s.key.PubKey(),
				},
			},
		}
		rawLeaf, err := leaf.Encode()
		if err != nil {
			return err
		}
		expected, err := oortx.BuildCheckpointPSBT(
			arkscript.CheckpointPolicy{
				OperatorKey: s.key.PubKey(),
				CSVDelay:    10,
			}, oortx.CheckpointInput{
				SpentVTXO: oortx.SpentVTXORef{
					Outpoint: op,
					Output: wire.NewTxOut(
						int64(coin.VTXO.ValueSat),
						coin.VTXO.PkScript,
					),
				}, OwnerLeafPolicy: rawLeaf},
		)
		if err != nil {
			return err
		}
		expected.PSBT.UnsignedTx.TxIn[0].Sequence = path.RequiredSequence
		expected.PSBT.UnsignedTx.LockTime = path.RequiredLockTime
		if packet.UnsignedTx.TxHash() != expected.PSBT.UnsignedTx.TxHash() || len(
			packet.Inputs,
		) != 1 || packet.Inputs[0].WitnessUtxo == nil || packet.Inputs[0].WitnessUtxo.Value != int64(
			coin.VTXO.ValueSat,
		) || !bytes.Equal(
			packet.Inputs[0].WitnessUtxo.PkScript,
			coin.VTXO.PkScript,
		) {

			return status.Error(
				codes.InvalidArgument,
				"refund checkpoint differs from canonical "+
					"sender checkpoint",
			)
		}
		if err := signPacketInput(
			packet, 0, receiver, path,
		); err != nil {

			return status.Error(codes.InvalidArgument, err.Error())
		}
		signature := packet.Inputs[0].TaprootScriptSpendSig[len(
			packet.Inputs[0].TaprootScriptSpendSig,
		)-1]
		response = &swaprpc.AuthorizeInSwapRefundResponse{FailureReason: r.Failure, Signature: &swaprpc.TaprootScriptSignature{
			Pubkey: receiver.PubKey().SerializeCompressed(), WitnessScript: path.WitnessScript, Signature: signature.Signature}}
		return s.put("refund-authorization/"+id, response)
	})
	return response, err
}
