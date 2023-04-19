package randlottery

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	libstate "github.com/dedis/protean/libstate/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func DemuxRequest(input *base.ExecuteInput, vdata *core.VerificationData) (
	base.ExecutionFn, *base.GenericInput, *core.VerificationData,
	map[string][]byte, error) {
	var opHashes map[string][]byte
	switch input.FnName {
	case "join_randlot":
		var joinIn JoinInput
		err := protobuf.Decode(input.Data, &joinIn)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		return JoinLottery, &base.GenericInput{I: joinIn}, vdata, nil, nil
	case "batch_join_randlot":
		var batchJoinIn BatchJoinInput
		err := protobuf.Decode(input.Data, &batchJoinIn)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		return BatchJoinLottery, &base.GenericInput{I: batchJoinIn}, vdata, nil,
			nil
	case "close_randlot":
		var closeIn CloseInput
		err := protobuf.Decode(input.Data, &closeIn)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		pr, ok := input.StateProofs["readset"]
		if !ok {
			return nil, nil, nil, nil, xerrors.New("missing input: readset")
		}
		closeIn.BlkHeight = pr.Proof.Latest.Index
		vdata.InputHashes = getCloseHashes(input.FnName, &closeIn)
		vdata.StateProofs = input.StateProofs
		return CloseLottery, &base.GenericInput{I: closeIn}, vdata, nil, nil
	case "finalize_randlot":
		var finalizeIn FinalizeInput
		err := protobuf.Decode(input.Data, &finalizeIn)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		vdata.InputHashes, opHashes, err = getFinalizeHashes(input.FnName, &finalizeIn)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		return FinalizeLottery, &base.GenericInput{I: finalizeIn}, vdata, opHashes, nil
	default:
	}
	return nil, nil, nil, nil, nil
}

func MuxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "join_randlot":
		joinOut, ok := genericOut.O.(JoinOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&joinOut)
		if err != nil {
			return nil, nil, err
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(joinOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	case "batch_join_randlot":
		joinOut, ok := genericOut.O.(JoinOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&joinOut)
		if err != nil {
			return nil, nil, err
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(joinOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	case "close_randlot":
		closeOut, ok := genericOut.O.(CloseOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&closeOut)
		if err != nil {
			return nil, nil, xerrors.Errorf("encoding output: %v", err)
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(closeOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	case "finalize_randlot":
		finalizeOut, ok := genericOut.O.(FinalizeOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&finalizeOut)
		if err != nil {
			return nil, nil, xerrors.Errorf("encoding output: %v", err)
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(finalizeOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	default:
	}
	return nil, nil, nil
}

func getCloseHashes(fnName string, input *CloseInput) map[string][]byte {
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	inputHashes["barrier"] = utils.HashUint64(uint64(input.Barrier))
	return inputHashes
}

func getFinalizeHashes(fnName string, input *FinalizeInput) (map[string][]byte, map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	receiptHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	inputHashes["round"] = utils.HashUint64(input.Round)
	buf, err := input.Randomness.Hash()
	if err != nil {
		log.Errorf("calculating the randomness hash: %v", err)
		return nil, nil, err
	}
	inputHashes["randomness"] = buf
	receiptHashes["randomness"] = buf
	return inputHashes, receiptHashes, nil
}
