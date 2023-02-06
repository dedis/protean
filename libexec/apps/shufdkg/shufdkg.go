package shufdkg

import (
	"github.com/dedis/protean/core"
	easyneff "github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/libexec/base"
	threshold "github.com/dedis/protean/threshold/base"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/protobuf"
)

func PrepareShuffle(input *base.ExecuteInput) (*base.ExecuteOutput, map[string][]byte, error) {
	var prepShufInput PrepareShufInput
	err := protobuf.Decode(input.Data, &prepShufInput)
	if err != nil {
		return nil, nil, err
	}
	shInput := &easyneff.ShuffleInput{Pairs: prepShufInput.Pairs}
	//output := &base.ExecuteOutput{O: *shInput}
	data, err := protobuf.Encode(shInput)
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
}

func PrepareDecrypt(input *base.ExecuteInput) (*base.ExecuteOutput, map[string][]byte, error) {
	var prepDecInput PrepareDecInput
	err := protobuf.Decode(input.Data, &prepDecInput)
	if err != nil {
		return nil, nil, err
	}
	shProof := prepDecInput.ShufProof
	inputHashes, err := getInputHashes(&shProof)
	if err != nil {
		log.Errorf("failed to create input hashes: %v", err)
		return nil, nil, err
	}
	err = runVerification(&input.ExecReq, inputHashes)
	if err != nil {
		log.Errorf("failed to verify execution request: %v", err)
		return nil, nil, err
	}
	sz := len(shProof.Proofs)
	pairs := shProof.Proofs[sz-1].Pairs
	decInput := &threshold.DecryptInput{ElGamalPairs: pairs}
	data, err := protobuf.Encode(decInput)
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
}

func getInputHashes(shProof *easyneff.ShuffleProof) (map[string][]byte, error) {
	inputHashes := make(map[string][]byte)
	hash, err := shProof.Hash()
	if err != nil {
		return nil, err
	}
	inputHashes["proofs"] = hash
	return inputHashes, nil
}

func runVerification(execReq *core.ExecutionRequest, hashes map[string][]byte) error {
	vData := &core.VerificationData{
		UID:         base.UID,
		OpcodeName:  base.EXEC,
		InputHashes: hashes,
	}
	return execReq.Verify(vData)
}
