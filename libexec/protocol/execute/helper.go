package execute

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/apps/dkglottery"
	"github.com/dedis/protean/libexec/apps/evoting"
	"github.com/dedis/protean/libexec/apps/randlottery"
	"github.com/dedis/protean/libexec/apps/shufdkg"
	"github.com/dedis/protean/libexec/base"
)

func demuxRequest(input *base.ExecuteInput) (base.ExecutionFn,
	*base.GenericInput, *core.VerificationData, error) {
	vdata := &core.VerificationData{UID: base.UID, OpcodeName: base.EXEC}
	switch input.FnName {
	case "prep_shuf", "prep_dec":
		return shufdkg.DemuxRequest(input, vdata)
	case "join_randlot", "close_randlot", "finalize_randlot":
		return randlottery.DemuxRequest(input, vdata)
	case "setup_dkglot", "join_dkglot", "close_dkglot",
		"prepare_decrypt_dkglot", "finalize_dkglot":
		return dkglottery.DemuxRequest(input, vdata)
	case "setup_vote", "vote", "close_vote", "prepare_shuffle",
		"prepare_proofs", "prepare_decrypt_vote", "tally":
		return evoting.DemuxRequest(input, vdata)
	default:
	}
	return nil, nil, nil, nil
}

func muxRequest(fnName string, genericOut *base.GenericOutput) (*base.ExecuteOutput, map[string][]byte, error) {
	switch fnName {
	case "prep_shuf", "prep_dec":
		return shufdkg.MuxRequest(fnName, genericOut)
	case "join_randlot", "close_randlot", "finalize_randlot":
		return randlottery.MuxRequest(fnName, genericOut)
	case "setup_dkglot", "join_dkglot", "close_dkglot",
		"prepare_decrypt_dkglot", "finalize_dkglot":
		return dkglottery.MuxRequest(fnName, genericOut)
	case "setup_vote", "vote", "close_vote", "prepare_shuffle",
		"prepare_proofs", "prepare_decrypt_vote", "tally":
		return evoting.MuxRequest(fnName, genericOut)
	default:
	}
	return nil, nil, nil
}
