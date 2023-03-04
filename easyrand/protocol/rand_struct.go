package protocol

import (
	"go.dedis.ch/onet/v3"
)

const DKGProtoName = "easyrand_dkg"
const SignProtoName = "easyrand_sign"

// Init initializes the message to sign.
type Init struct {
	Msg []byte
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
