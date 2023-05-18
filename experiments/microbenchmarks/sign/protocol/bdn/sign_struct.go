package bdn

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/blscosi/bdnproto"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
)

const BDNSignProtoName = "microbenchmark_bdn_sign"

func init() {
	network.RegisterMessages(&BDNSignRequest{}, &BDNSignResponse{})
}

type BDNSignRequest struct {
	OutputData map[string][]byte
	ExecReq    *core.ExecutionRequest
}

type structBDNSign struct {
	*onet.TreeNode
	BDNSignRequest
}

type BDNSignResponse struct {
	Signatures map[string]bdnproto.BdnSignature
}

type structBDNSignResponse struct {
	*onet.TreeNode
	BDNSignResponse
}
