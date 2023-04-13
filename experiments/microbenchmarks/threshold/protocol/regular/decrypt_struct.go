package regular

import (
	"github.com/dedis/protean/threshold/base"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
)

const RegularDecryptProtoName = "decrypt_reg"

type Partial struct {
	Shares []*share.PubShare
	Eis    []kyber.Scalar
	Fis    []kyber.Scalar
	Pubs   []kyber.Point
}

type DecryptShare struct {
	*base.DecryptInput
}

type structDecryptShare struct {
	*onet.TreeNode
	DecryptShare
}

type Share struct {
	Sh *share.PubShare
	Ei kyber.Scalar
	Fi kyber.Scalar
}

type DecryptShareResponse struct {
	Shares []Share
}

type structDecryptShareResponse struct {
	*onet.TreeNode
	DecryptShareResponse
}
