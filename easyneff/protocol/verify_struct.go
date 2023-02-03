package protocol

import (
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/utils"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const VerifyProtoName = "easyneff_verify"

type VerificationFn func(*ShuffleProof, kyber.Point, kyber.Point,
	utils.ElGamalPairs, []kyber.Point) error

type VerifyProofs struct {
	ShufInput base.ShuffleInput
	ShufProof ShuffleProof
	Hash      []byte
}

type structVerifyProofs struct {
	*onet.TreeNode
	VerifyProofs
}

type VerifyProofsResponse struct {
	Signature blscosi.BlsSignature
}

type structVerifyProofsResponse struct {
	*onet.TreeNode
	VerifyProofsResponse
}
