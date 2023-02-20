package shufdkg

import (
	"github.com/dedis/protean/core"
	easyneff "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/libexec/base"
	threshold "github.com/dedis/protean/threshold/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func DemuxRequest(fnName string, input *base.ExecuteInput, vdata *core.VerificationData) (base.ExecutionFn,
	*base.GenericInput, *core.VerificationData, error) {
	switch fnName {
	case "prep_shuf":
		var prepShufInput PrepareShufInput
		err := protobuf.Decode(input.Data, &prepShufInput)
		if err != nil {
			return nil, nil, nil, err
		}
		return PrepareShuffle, &base.GenericInput{I: prepShufInput}, vdata, nil
	case "prep_dec":
		var prepDecInput PrepareDecInput
		err := protobuf.Decode(input.Data, &prepDecInput)
		if err != nil {
			return nil, nil, nil, err
		}
		inputHashes, err := getInputHashes(&prepDecInput)
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("failed to create input hashes: %v", err)
		}
		vdata.InputHashes = inputHashes
		return PrepareDecrypt, &base.GenericInput{I: prepDecInput}, vdata, nil
	default:
	}
	return nil, nil, nil, nil
}

func MuxRequest(fnName string, genericOut *base.GenericOutput) (*base.
	ExecuteOutput, map[string][]byte, error) {
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
		pairsHash, err := shInput.Pairs.Hash()
		if err != nil {
			return nil, nil, err
		}
		outputHashes := make(map[string][]byte)
		outputHashes["pairs"] = pairsHash
		ptHash, err := utils.Hash(shInput.H)
		if err != nil {
			return nil, nil, err
		}
		outputHashes["h"] = ptHash
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

func getInputHashes(prepDecInput *PrepareDecInput) (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	hash, err := prepDecInput.ShufProof.Hash()
	if err != nil {
		return nil, err
	}
	inputHashes["proofs"] = hash
	return inputHashes, nil
}
