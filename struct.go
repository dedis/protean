package protean

import (
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
)

type UnitStorage struct {
	UnitID   string
	Txns     map[string]string
	CompKeys []kyber.Point
}

type WfNode struct {
	UID  string
	TID  string
	Deps []int
}

type CreateSkipchainRequest struct {
	Roster  *onet.Roster
	MHeight int
	BHeight int
}

type CreateSkipchainReply struct {
	Genesis []byte
	Sb      *skipchain.SkipBlock
}

type InitUnitRequest struct {
	//Genesis      []byte
	UnitID       string
	Txns         map[string]string
	CompilerKeys []kyber.Point
}
