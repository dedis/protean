package base

import (
	"github.com/dedis/protean/core"
)

const (
	UID  string = "codeexec"
	EXEC string = "exec"
)

type ExecutionFn func(input *ExecuteInput) (*ExecuteOutput, map[string][]byte, error)

type ExecuteInput struct {
	//I       interface{}
	Data    []byte
	ExecReq core.ExecutionRequest
}

type ExecuteOutput struct {
	//O interface{}
	Data []byte
}
