package randlottery

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	libstate "github.com/dedis/protean/libstate/base"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

func DemuxRequest(fnName string, input *base.ExecuteInput,
	vdata *core.VerificationData) (base.ExecutionFn, *base.GenericInput,
	*core.VerificationData, error) {
	switch fnName {
	case "join_lottery":
		var joinIn JoinLotteryInput
		err := protobuf.Decode(input.Data, &joinIn)
		if err != nil {
			return nil, nil, nil, err
		}
		vdata.StateProofs = input.StateProofs
		return JoinLottery, &base.GenericInput{I: joinIn}, vdata, nil
	default:
	}
	return nil, nil, nil, nil
}

func MuxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "join_lottery":
		joinOut, ok := genericOut.O.(JoinLotteryOutput)
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
	default:
	}
	return nil, nil, nil
}
