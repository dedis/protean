package libexec

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
)

type RegistryData struct {
	RID             byzcoin.InstanceID
	RegistryProof   byzcoin.Proof
	RegistryGenesis skipchain.SkipBlock
}

type ContractData struct {
	CID          byzcoin.InstanceID
	StateProof   core.StateProof
	StateGenesis skipchain.SkipBlock
}

type InitTransaction struct {
	RData   RegistryData
	CData   ContractData
	WfName  string
	TxnName string
}

type InitTransactionReply struct {
}
