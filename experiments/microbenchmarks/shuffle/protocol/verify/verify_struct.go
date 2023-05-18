package verify

import (
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const VerifyProtoName = "mb_shuffle_verify"

func init() {
	network.RegisterMessages(&VerifyProofs{}, &VerifyProofsResponse{})
}

type VerificationFn func(*base.ShuffleOutput, kyber.Point, kyber.Point,
	utils.ElGamalPairs, []kyber.Point) error

type VerifyProofs struct {
	ShufInput  *base.ShuffleInput
	ShufOutput *base.ShuffleOutput
}

type structVerifyProofs struct {
	*onet.TreeNode
	VerifyProofs
}

type VerifyProofsResponse struct {
	Signatures map[string]bdnproto.BdnSignature
}

type structVerifyProofsResponse struct {
	*onet.TreeNode
	VerifyProofsResponse
}
