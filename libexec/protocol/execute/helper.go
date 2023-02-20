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
	default:
	}
	return nil, nil, nil
}
