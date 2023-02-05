package protocol

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand/base"
	"go.dedis.ch/onet/v3"
)

const DKGProtoName = "easyrand_dkg"
const SignProtoName = "easyrand_sign"

// Init initializes the message to sign.
type Init struct {
	Msg     []byte
	Input   *base.RandomnessInput
	ExecReq *core.ExecutionRequest
}
type initChan struct {
	*onet.TreeNode
	Init
}

// Sig contains the full signature.
type Sig struct {
	ThresholdSig []byte
}
type sigChan struct {
	*onet.TreeNode
	Sig
}

// Sync is a synchronisation message.
type Sync struct{}

type syncChan struct {
	*onet.TreeNode
	Sync
}
