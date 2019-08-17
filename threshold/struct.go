package threshold

import (
	"time"

	protean "github.com/dedis/protean"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

const NameDecrypt = "Decrypt"

type pubPoly struct {
	B       kyber.Point
	Commits []kyber.Point
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

type Ciphertext struct {
	U    kyber.Point
	Ubar kyber.Point
	E    kyber.Scalar
	F    kyber.Scalar
	C    kyber.Point
}

type DecryptRequest struct {
	ID string
	C  kyber.Point
	U  kyber.Point
	Xc kyber.Point
}

type DecryptReply struct {
	C       kyber.Point
	X       kyber.Point
	XhatEnc kyber.Point
}

type SpawnDarcRequest struct {
	Darc darc.Darc
	Wait int
}

type SpawnDarcReply struct {
}
