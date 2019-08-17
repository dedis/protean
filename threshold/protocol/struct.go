package protocol

import (
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
)

const NameDecrypt = "Decrypt"

type PartialDecrypt struct {
	U  kyber.Point
	Xc kyber.Point // optional
}

type structPartialDecrypt struct {
	*onet.TreeNode
	PartialDecrypt
}

type PartialDecryptReply struct {
	Ui *share.PubShare
	Ei kyber.Scalar
	Fi kyber.Scalar
}

type structPartialDecryptReply struct {
	*onet.TreeNode
	PartialDecryptReply
}
