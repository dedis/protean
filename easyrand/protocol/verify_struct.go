package protocol

import (
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const VerifyProtoName = "easyrand_verify"

type Data struct {
	Public kyber.Point
	Round  uint64
	Prev   []byte
	Value  []byte
}

type VerifyRand struct {
	Hash []byte
}

type structVerifyRand struct {
	*onet.TreeNode
	VerifyRand
}

type VerifyResponse struct {
	Signature blscosi.BlsSignature
}

type structVerifyResponse struct {
	*onet.TreeNode
	VerifyResponse
}
