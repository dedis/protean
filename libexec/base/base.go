package base

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
)

const (
	UID  string = "codeexec"
	EXEC string = "exec"
)

type ByzData struct {
	IID     byzcoin.InstanceID
	Proof   byzcoin.Proof
	Genesis skipchain.SkipBlock
}

type InitTxnInput struct {
	RData  ByzData
	CData  ByzData
	WfName string

	TxnName string
}

type ExecutionFn func(input *GenericInput) (*GenericOutput, error)

type ExecuteInput struct {
	FnName      string
	Data        []byte
	StateProofs map[string]*core.StateProof
}

type ExecuteOutput struct {
	Data []byte
}

type GenericInput struct {
	I       interface{}
	KVDicts map[string]core.KVDict
}

type GenericOutput struct {
	O interface{}
}
