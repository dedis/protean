package execute

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/apps/randlottery"
	"github.com/dedis/protean/libexec/apps/shufdkg"
	"github.com/dedis/protean/libexec/base"
)

func demuxRequest(fnName string, input *base.ExecuteInput) (base.ExecutionFn,
	*base.GenericInput, *core.VerificationData, error) {
	vdata := &core.VerificationData{UID: base.UID, OpcodeName: base.EXEC}
	switch fnName {
	case "prep_shuf", "prep_dec":
		return shufdkg.DemuxRequest(fnName, input, vdata)
	case "join_lottery":
		return randlottery.DemuxRequest(fnName, input, vdata)
		//var prepShufInput shufdkg.PrepareShufInput
		//err := protobuf.Decode(input.Data, &prepShufInput)
		//if err != nil {
		//	return nil, nil, nil, err
		//}
		//return shufdkg.PrepareShuffle, &base.GenericInput{I: prepShufInput}, vdata, nil
	//case "prep_dec":
	//var prepDecInput shufdkg.PrepareDecInput
	//err := protobuf.Decode(input.Data, &prepDecInput)
	//if err != nil {
	//	return nil, nil, nil, err
	//}
	//inputHashes, err := getInputHashes(&prepDecInput)
	//if err != nil {
	//	return nil, nil, nil, xerrors.Errorf("failed to create input hashes: %v", err)
	//}
	//vdata.InputHashes = inputHashes
	//return shufdkg.PrepareDecrypt, &base.GenericInput{I: prepDecInput}, vdata, nil
	default:
	}
	return nil, nil, nil, nil
}

func muxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "prep_shuf", "prep_dec":
		return shufdkg.MuxRequest(fnName, genericOut)
	case "join_lottery":
		return randlottery.MuxRequest(fnName, genericOut)
	//case "prep_shuf":
	//	shInput, ok := genericOut.O.(easyneff.ShuffleInput)
	//	if !ok {
	//		return nil, nil, xerrors.New("missing output")
	//	}
	//	data, err := protobuf.Encode(&shInput)
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//	output := &base.ExecuteOutput{Data: data}
	//	pairsHash, err := shInput.Pairs.Hash()
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//	outputHashes := make(map[string][]byte)
	//	outputHashes["pairs"] = pairsHash
	//	ptHash, err := utils.Hash(shInput.H)
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//	outputHashes["h"] = ptHash
	//	return output, outputHashes, nil
	//case "prep_dec":
	//	decInput, ok := genericOut.O.(threshold.DecryptInput)
	//	if !ok {
	//		return nil, nil, xerrors.New("missing output")
	//	}
	//	data, err := protobuf.Encode(&decInput)
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//	output := &base.ExecuteOutput{Data: data}
	//	hash, err := decInput.Hash()
	//	if err != nil {
	//		return nil, nil, err
	//	}
	//	outputHashes := make(map[string][]byte)
	//	outputHashes["ciphertexts"] = hash
	//	return output, outputHashes, nil
	default:
	}
	return nil, nil, nil
}
