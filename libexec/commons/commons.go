package commons

import "github.com/dedis/protean/core"

//TODO: add execution request to input parameters
type ExecutionFn func([]core.OpcodeRequest) ([]core.Output, error)
