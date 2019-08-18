package threshold

import (
	"time"

	"github.com/dedis/protean"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const ThreshProtoName = "ThreshDecryptProto"

type Ciphertext struct {
	C1 kyber.Point
	C2 kyber.Point
}

type InitUnitRequest struct {
	Roster       *onet.Roster
	ScData       *protean.ScInitData
	BaseStore    *protean.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
}

type InitDKGRequest struct {
	ID string
}

type InitDKGReply struct {
	X kyber.Point
}

type DecryptRequest struct {
	ID         string
	Ciphertext *Ciphertext
}

type DecryptReply struct {
	DecPt kyber.Point
}

// Protocol messages

type PartialRequest struct {
	Ciphertext *Ciphertext
}

type structPartialRequest struct {
	*onet.TreeNode
	PartialRequest
}

type PartialReply struct {
	Index   int
	Partial kyber.Point
}

type structPartialReply struct {
	*onet.TreeNode
	PartialReply
}
