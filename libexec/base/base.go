package base

import "github.com/dedis/protean/core"

const (
	UID  string = "codeexec"
	EXEC string = "exec"
)

type ExecutionFn func(input *GenericInput) (*GenericOutput, error)

type ExecuteInput struct {
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
