package randlottery

import (
	"crypto/sha256"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	libstate "github.com/dedis/protean/libstate/base"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
	"strconv"
)

func DemuxRequest(input *base.ExecuteInput,
	vdata *core.VerificationData) (base.ExecutionFn, *base.GenericInput,
	*core.VerificationData, error) {
	switch input.FnName {
	case "join_lottery":
		var joinIn JoinInput
		err := protobuf.Decode(input.Data, &joinIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = base.GetFnHash(input.FnName)
		vdata.InputHashes = inputHashes
		return JoinLottery, &base.GenericInput{I: joinIn}, vdata, nil
	case "close_lottery":
		var closeIn CloseInput
		err := protobuf.Decode(input.Data, &closeIn)
		if err != nil {
			return nil, nil, nil, err
		}
		pr, ok := input.StateProofs["readset"]
		if !ok {
			return nil, nil, nil, xerrors.New("missing input: readset")
		}
		closeIn.BlkHeight = len(pr.Proof.Links)
		vdata.InputHashes = getCloseHashes(input.FnName, &closeIn)
		vdata.StateProofs = input.StateProofs
		return CloseLottery, &base.GenericInput{I: closeIn}, vdata, nil
	case "finalize_lottery":
		var finalizeIn FinalizeInput
		err := protobuf.Decode(input.Data, &finalizeIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.InputHashes = getFinalizeHashes(input.FnName, &finalizeIn)
		vdata.StateProofs = input.StateProofs
		return FinalizeLottery, &base.GenericInput{I: finalizeIn}, vdata, nil
	default:
	}
	return nil, nil, nil, nil
}

func MuxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "join_lottery":
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
	case "close_lottery":
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
	case "finalize_lottery":
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
	inputHashes["fnname"] = base.GetFnHash(fnName)
	h := sha256.New()
	val := strconv.Itoa(input.Barrier)
	h.Write([]byte(val))
	inputHashes["barrier"] = h.Sum(nil)
	return inputHashes
}

func getFinalizeHashes(fnName string, input *FinalizeInput) map[string][]byte {
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = base.GetFnHash(fnName)
	//h := sha256.New()
	//val := strconv.Itoa(input.Barrier)
	//h.Write([]byte(val))
	//inputHashes["barrier"] = h.Sum(nil)
	return inputHashes
}
