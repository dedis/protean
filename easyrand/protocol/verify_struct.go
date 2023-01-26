package protocol

import (
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
)

const VerifyProtoName = "easyrand_verify"

type Data struct {
	Round uint64
	Prev  []byte
	Value []byte
}

type VerifyRandomness struct {
	Hash []byte
}

type structVerifyRandomness struct {
	*onet.TreeNode
	VerifyRandomness
}

type VerifyRandomnessResponse struct {
	Signature blscosi.BlsSignature
}

type structVerifyRandomnessResponse struct {
	*onet.TreeNode
	VerifyRandomnessResponse
}
