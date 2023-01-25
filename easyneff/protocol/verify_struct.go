package protocol

import (
	"github.com/dedis/protean/utils"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const ShuffleVerifyName = "ShuffleVerifyProto"

type VerificationFn func(*ShuffleProof, kyber.Point, kyber.Point,
	[]utils.ElGamalPair, []kyber.Point) error

type VerifyProofs struct {
	Pairs  []utils.ElGamalPair
	H      kyber.Point
	SProof ShuffleProof
	Hash   []byte
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
