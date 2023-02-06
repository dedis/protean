package protocol

import (
	"github.com/dedis/protean/easyneff/base"
	"go.dedis.ch/onet/v3/network"
)

const ShuffleProtoName = "easyneff_shuffle"

func init() {
	network.RegisterMessages(&base.ShuffleInput{})
}

type Request struct {
	ShuffleInput *base.ShuffleInput
	//ExecReq      *core.ExecutionRequest
}
