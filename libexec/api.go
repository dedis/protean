package libexec

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"golang.org/x/xerrors"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit() (*InitUnitReply, error) {
	req := &InitUnit{Roster: c.roster}
	reply := &InitUnitReply{}
	for _, node := range c.roster.List {
		err := c.SendProtobuf(node, req, reply)
		if err != nil {
			return nil, xerrors.Errorf("send InitUnit message: %v", err)
		}
	}
	return reply, nil
}

func (c *Client) InitTransaction(rdata base.ByzData, cdata base.ByzData, wf string,
	txn string) (*InitTransactionReply, error) {
	reply := &InitTransactionReply{}
	req := &InitTransaction{
		Input: base.InitTxnInput{
			RData:   rdata,
			CData:   cdata,
			WfName:  wf,
			TxnName: txn,
		},
	}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("sending init transaction message: %v", err)
	}
	return reply, nil
}

func (c *Client) Execute(input base.ExecuteInput, execReq *core.ExecutionRequest) (*ExecuteReply,
	error) {
	reply := &ExecuteReply{}
	req := &Execute{
		Input:   input,
		ExecReq: *execReq,
	}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	if err != nil {
		return nil, xerrors.Errorf("sending execute request: %v", err)
	}
	return reply, nil
}
