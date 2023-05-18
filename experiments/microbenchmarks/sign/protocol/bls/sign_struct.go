package bls

import (
	"github.com/dedis/protean/core"
	blscosi "go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const BLSSignProtoName = "microbenchmark_bls_sign"

func init() {
	network.RegisterMessages(&BLSSignRequest{}, &BLSSignResponse{})
}

type BLSSignRequest struct {
	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
}

type structBLSSign struct {
	*onet.TreeNode
	BLSSignRequest
}

type BLSSignResponse struct {
	Signatures map[string]blscosi.BlsSignature
}

type structBLSSignResponse struct {
	*onet.TreeNode
	BLSSignResponse
}
