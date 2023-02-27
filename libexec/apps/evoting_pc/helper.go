package evotingpc

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
	case "setup_vote_pc":
		var setupIn SetupInput
		err := protobuf.Decode(input.Data, &setupIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		vdata.InputHashes, err = getSetupHashes(input.FnName, &setupIn)
		return Setup, &base.GenericInput{I: setupIn}, vdata, nil
	case "vote_pc":
		var voteIn VoteInput
		err := protobuf.Decode(input.Data, &voteIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		return Vote, &base.GenericInput{I: voteIn}, vdata, nil
	case "lock":
		var lockIn LockInput
		err := protobuf.Decode(input.Data, &lockIn)
		if err != nil {
			return nil, nil, nil, err
		}
		pr, ok := input.StateProofs["readset"]
		if !ok {
			return nil, nil, nil, xerrors.New("missing input: readset")
		}
		lockIn.BlkHeight = len(pr.Proof.Links)
		vdata.InputHashes = getLockHashes(input.FnName, &lockIn)
		vdata.StateProofs = input.StateProofs
		vdata.Precommits = input.Precommits
		return Lock, &base.GenericInput{I: lockIn, Precommits: input.Precommits}, vdata, nil
	case "prepare_shuffle_pc":
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		vdata.StateProofs = input.StateProofs
		return PrepareShuffle, &base.GenericInput{I: nil}, vdata, nil
	case "prepare_proofs_pc":
		var storeIn PrepProofsInput
		err := protobuf.Decode(input.Data, &storeIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.InputHashes, err = getPrepProofHashes(input.FnName, &storeIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		return PrepareProofs, &base.GenericInput{I: storeIn}, vdata, nil
	case "prepare_decrypt_vote_pc":
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		vdata.StateProofs = input.StateProofs
		return PrepareDecrypt, &base.GenericInput{I: nil}, vdata, nil
	case "tally_pc":
		var tallyIn TallyInput
		err := protobuf.Decode(input.Data, &tallyIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.InputHashes, err = getTallyHashes(input.FnName, &tallyIn)
		if err != nil {
			log.Errorf("calculating tally hashes: %v", err)
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		return Tally, &base.GenericInput{I: tallyIn}, vdata, nil
	default:
	}
	return nil, nil, nil, nil
}

func MuxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "setup_vote_pc":
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
	case "vote_pc":
		voteOut, ok := genericOut.O.(VoteOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&voteOut)
		if err != nil {
			return nil, nil, err
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(voteOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	case "lock":
		lockOut, ok := genericOut.O.(LockOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&lockOut)
		if err != nil {
			return nil, nil, xerrors.Errorf("encoding output: %v", err)
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(lockOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	case "prepare_shuffle_pc":
		prepShufOut, ok := genericOut.O.(PrepShufOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&prepShufOut)
		if err != nil {
			return nil, nil, xerrors.Errorf("encoding output: %v", err)
		}
		output := &base.ExecuteOutput{Data: data}
		outputHashes, err := prepShufOut.Input.PrepareHashes()
		if err != nil {
			return nil, nil, err
		}
		return output, outputHashes, nil
	case "prepare_proofs_pc":
		prepProofsOut, ok := genericOut.O.(PrepProofsOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&prepProofsOut)
		if err != nil {
			return nil, nil, xerrors.Errorf("encoding output: %v", err)
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(prepProofsOut.WS)
		outputHashes := make(map[string][]byte)
		outputHashes["writeset"] = wsHash
		return output, outputHashes, nil
	case "prepare_decrypt_vote_pc":
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
	case "tally_pc":
		tallyOut, ok := genericOut.O.(TallyOutput)
		if !ok {
			return nil, nil, xerrors.New("missing output")
		}
		data, err := protobuf.Encode(&tallyOut)
		if err != nil {
			return nil, nil, xerrors.Errorf("encoding output: %v", err)
		}
		output := &base.ExecuteOutput{Data: data}
		wsHash := libstate.Hash(tallyOut.WS)
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

func getLockHashes(fnName string, input *LockInput) map[string][]byte {
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	inputHashes["barrier"] = utils.HashUint64(uint64(input.Barrier))
	return inputHashes
}

func getPrepProofHashes(fnName string, input *PrepProofsInput) (
	map[string][]byte, error) {
	var err error
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	inputHashes["proofs"], err = input.ShProofs.Hash()
	if err != nil {
		log.Errorf("calculating the proofs hash: %v", err)
		return nil, err
	}
	return inputHashes, nil
}

func getTallyHashes(fnName string, input *TallyInput) (map[string][]byte,
	error) {
	inputHashes := make(map[string][]byte)
	inputHashes["fnname"] = utils.HashString(fnName)
	buf, err := utils.HashPoints(input.Ps)
	if err != nil {
		log.Errorf("calculating the dec_ballots hash: %v", err)
		return nil, err
	}
	inputHashes["candidate_count"] = utils.HashUint64(uint64(input.CandCount))
	inputHashes["plaintexts"] = buf
	return inputHashes, nil
}
