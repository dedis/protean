package evoting

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
	case "setup_vote":
		var setupIn SetupInput
		err := protobuf.Decode(input.Data, &setupIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		vdata.InputHashes, err = getSetupHashes(input.FnName, &setupIn)
		return Setup, &base.GenericInput{I: setupIn}, vdata, nil
	case "vote":
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
	case "close_vote":
		var closeIn CloseInput
		err := protobuf.Decode(input.Data, &closeIn)
		if err != nil {
			return nil, nil, nil, err
		}
		pr, ok := input.StateProofs["readset"]
		if !ok {
			return nil, nil, nil, xerrors.New("missing input: readset")
		}
		closeIn.BlkHeight = pr.Proof.Latest.Index
		vdata.InputHashes = getCloseHashes(input.FnName, &closeIn)
		vdata.StateProofs = input.StateProofs
		return CloseVote, &base.GenericInput{I: closeIn}, vdata, nil
	case "prepare_shuffle":
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		vdata.StateProofs = input.StateProofs
		return PrepareShuffle, &base.GenericInput{I: nil}, vdata, nil
	case "prepare_proofs":
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
	case "prepare_decrypt_vote":
		inputHashes := make(map[string][]byte)
		inputHashes["fnname"] = utils.HashString(input.FnName)
		vdata.InputHashes = inputHashes
		vdata.StateProofs = input.StateProofs
		return PrepareDecrypt, &base.GenericInput{I: nil}, vdata, nil
	case "tally":
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
	case "setup_vote":
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
	case "vote":
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
	case "close_vote":
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
	case "prepare_shuffle":
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
	case "prepare_proofs":
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
	case "prepare_decrypt_vote":
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
	case "tally":
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

func getCloseHashes(fnName string, input *CloseInput) map[string][]byte {
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
