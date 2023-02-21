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

func DemuxRequest(input *base.ExecuteInput, vdata *core.VerificationData) (base.ExecutionFn,
	*base.GenericInput, *core.VerificationData, error) {
	switch input.FnName {
	case "prep_shuf":
		var prepShufInput PrepareShufInput
		err := protobuf.Decode(input.Data, &prepShufInput)
		if err != nil {
			return nil, nil, nil, err
		}
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = base.GetFnHash(input.FnName)
		vdata.InputHashes = inputHashes
		return PrepareShuffle, &base.GenericInput{I: prepShufInput}, vdata, nil
	case "prep_dec":
		var prepDecInput PrepareDecInput
		err := protobuf.Decode(input.Data, &prepDecInput)
		if err != nil {
			return nil, nil, nil, err
		}
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = base.GetFnHash(input.FnName)
		hash, err := prepDecInput.ShufProof.Hash()
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("calculating the hash: %v",
				err)
		}
		inputHashes["proofs"] = hash
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
