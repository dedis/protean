package protocol

import (
	"github.com/dedis/protean/easyneff/base"
	"go.dedis.ch/onet/v3/network"
)

const ShuffleProtoName = "easyneff_shuffle"

func init() {
	network.RegisterMessages(&Request{}, &base.Proof{})
}

type Request struct {
	ShuffleInput *base.ShuffleInput
}
