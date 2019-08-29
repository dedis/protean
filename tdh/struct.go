package tdh

import (
	"time"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/onet/v3"
)

const TDHProtoName = "THDDecryptProto"

type DKGID [32]byte

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
}

type Ciphertext struct {
	U    kyber.Point
	Ubar kyber.Point
	E    kyber.Scalar
	F    kyber.Scalar
	C    kyber.Point
}

type InitUnitRequest struct {
	Roster *onet.Roster
	//ScData       *protean.ScInitData
	//BaseStore    *protean.BaseStorage
	ScData       *sys.ScInitData
	BaseStore    *sys.BaseStorage
	BlkInterval  time.Duration
	DurationType time.Duration
}

type InitUnitReply struct {
	Genesis []byte
}

type InitDKGRequest struct {
	//ID string
	ID DKGID
}

type InitDKGReply struct {
	X kyber.Point
}

type DecryptRequest struct {
	//ID  string
	ID  DKGID
	Gen []byte
	Ct  *Ciphertext
	Xc  kyber.Point
	//C   kyber.Point
	//U   kyber.Point
}

type DecryptReply struct {
	C       kyber.Point
	X       kyber.Point
	XhatEnc kyber.Point
}

// Protocol messages

type PartialRequest struct {
	//U   kyber.Point
	Ct  *Ciphertext
	Xc  kyber.Point // optional
	Gen []byte
}

type structPartialRequest struct {
	*onet.TreeNode
	PartialRequest
}

type PartialReply struct {
	Ui *share.PubShare
	Ei kyber.Scalar
	Fi kyber.Scalar
}

type structPartialReply struct {
	*onet.TreeNode
	PartialReply
}
