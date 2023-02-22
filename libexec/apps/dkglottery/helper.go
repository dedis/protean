package dkglottery

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	libstate "github.com/dedis/protean/libstate/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func DemuxRequest(input *base.ExecuteInput,
	vdata *core.VerificationData) (base.ExecutionFn, *base.GenericInput,
	*core.VerificationData, error) {
	switch input.FnName {
	case "setup":
		var setupIn SetupInput
		err := protobuf.Decode(input.Data, &setupIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		vdata.InputHashes, err = getSetupHashes(input.FnName, &setupIn)
		return Setup, &base.GenericInput{I: setupIn}, vdata, nil
	case "join_dkglot":
		var joinIn JoinInput
		err := protobuf.Decode(input.Data, &joinIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		return JoinLottery, &base.GenericInput{I: joinIn}, vdata, nil
	case "close_dkglot":
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
	case "prepare_decrypt":
		vdata.StateProofs = input.StateProofs
		return PrepareDecrypt, &base.GenericInput{}, vdata, nil
	case "finalize_dkglot":
		var finalizeIn FinalizeInput
		err := protobuf.Decode(input.Data, &finalizeIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.InputHashes, err = getFinalizeHashes(input.FnName, &finalizeIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		return FinalizeLottery, &base.GenericInput{I: finalizeIn}, vdata, nil
	default:
	}
	return nil, nil, nil, nil
}

func MuxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "setup":
		setupOut, ok := genericOut.O.(SetupOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&setupOut)
		if err != nil {
			return nil, nil, err
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(setupOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	case "join_dkglot":
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
	case "close_dkglot":
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
	case "prepare_decrypt":
		prepDecOut, ok := genericOut.O.(PrepDecOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&prepDecOut)
		if err != nil {
			return nil, nil, xerrors.Errorf("encoding output: %v", err)
		}
		output := &base.ExecuteOutput{Data: data}
		hash, err := prepDecOut.Input.Hash()
		if err != nil {
			return nil, nil, err
		}
		outputHashes := make(map[string][]byte)
		outputHashes["ciphertexts"] = hash
		return output, outputHashes, nil
	case "finalize_dkglot":
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

func getSetupHashes(fnName string, input *SetupInput) (map[string][]byte,
	error) {
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	buf, err := utils.HashPoint(input.Pk)
	if err != nil {
		log.Errorf("calculating the public key hash: %v", err)
		return nil, err
	}
	inputHashes["pk"] = buf
	return inputHashes, nil
}

func getCloseHashes(fnName string, input *CloseInput) map[string][]byte {
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	inputHashes["barrier"] = utils.HashUint64(uint64(input.Barrier))
	return inputHashes
}

func getFinalizeHashes(fnName string, input *FinalizeInput) (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	buf, err := utils.HashPoints(input.Ps)
	if err != nil {
		log.Errorf("calculating the dec_tickets hash: %v", err)
		return nil, err
	}
	inputHashes["plaintexts"] = buf
	return inputHashes, nil
}
