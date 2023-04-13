package protocol

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const DummyProtoName = "microbenchmark_dummy"

func init() {
	network.RegisterMessages(&DummyRequest{}, &DummyResponse{})
}

type DummyRequest struct {
	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
}

type structDummy struct {
	*onet.TreeNode
	DummyRequest
}

type DummyResponse struct {
	OK bool
}

type structDummyResponse struct {
	*onet.TreeNode
	DummyResponse
}
