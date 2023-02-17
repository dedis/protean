package execute

import (
	"github.com/dedis/protean/core"
	easyneff "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/libexec/apps/shufdkg"
	"github.com/dedis/protean/libexec/base"
	threshold "github.com/dedis/protean/threshold/base"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func demuxRequest(fnName string, input *base.ExecuteInput) (base.ExecutionFn,
	*base.GenericInput, *core.VerificationData, error) {
	vdata := &core.VerificationData{UID: base.UID, OpcodeName: base.EXEC}
	switch fnName {
	case "prep_shuf":
		var prepShufInput shufdkg.PrepareShufInput
		err := protobuf.Decode(input.Data, &prepShufInput)
		if err != nil {
			return nil, nil, nil, err
		}
		return shufdkg.PrepareShuffle, &base.GenericInput{I: prepShufInput}, vdata, nil
	case "prep_dec":
		var prepDecInput shufdkg.PrepareDecInput
		err := protobuf.Decode(input.Data, &prepDecInput)
		if err != nil {
			return nil, nil, nil, err
		}
		inputHashes, err := getInputHashes(&prepDecInput)
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("failed to create input hashes: %v", err)
		}
		vdata.InputHashes = inputHashes
		return shufdkg.PrepareDecrypt, &base.GenericInput{I: prepDecInput}, vdata, nil
	default:
	}
	return nil, nil, nil, nil
}

func muxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "prep_shuf":
		shInput, ok := genericOut.O.(easyneff.ShuffleInput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&shInput)
		if err != nil {
			return nil, nil, err
		}
		output := &base.ExecuteOutput{Data: data}
		hash, err := shInput.Pairs.Hash()
		if err != nil {
			return nil, nil, err
		}
		outputHashes := make(map[string][]byte)
		outputHashes["pairs"] = hash
		return output, outputHashes, nil
	case "prep_dec":
		decInput, ok := genericOut.O.(threshold.DecryptInput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&decInput)
		if err != nil {
			return nil, nil, err
		}
		output := &base.ExecuteOutput{Data: data}
		hash, err := decInput.Hash()
		if err != nil {
			return nil, nil, err
		}
		outputHashes := make(map[string][]byte)
		outputHashes["ciphertexts"] = hash
		return output, outputHashes, nil
	default:
	}
	return nil, nil, nil
}

func getInputHashes(prepDecInput *shufdkg.PrepareDecInput) (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	hash, err := prepDecInput.ShufProof.Hash()
	if err != nil {
		return nil, err
	}
	inputHashes["proofs"] = hash
	return inputHashes, nil
}
