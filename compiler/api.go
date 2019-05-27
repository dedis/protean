package compiler

import (
	"errors"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) CreateSkipchain(r *onet.Roster, mHeight int, bHeight int) (*CreateSkipchainReply, error) {
	if len(r.List) == 0 {
		return nil, errors.New("Got an empty roster list")
	}
	dst := r.List[0]
	req := &CreateSkipchainRequest{
		Roster:  r,
		MHeight: mHeight,
		BHeight: bHeight,
	}
	reply := &CreateSkipchainReply{}
	err := c.SendProtobuf(dst, req, reply)
	return reply, err
}

//func (c *Client) CreateUnits(r *onet.Roster, req *CreateUnitsRequest) (*CreateUnitsReply, error) {
func (c *Client) CreateUnits(r *onet.Roster, genesis []byte, units []*FunctionalUnit) (*CreateUnitsReply, error) {
	//TODO: Check values in struct?
	if len(r.List) == 0 {
		return nil, errors.New("Got an empty roster list")
	}
	dst := r.List[0]
	req := &CreateUnitsRequest{
		Genesis: genesis,
		Units:   units,
	}
	reply := &CreateUnitsReply{}
	err := c.SendProtobuf(dst, req, reply)
	return reply, err
}

func (c *Client) GenerateExecutionPlan(r *onet.Roster, genesis []byte, wf []*WfNode) (*ExecPlanReply, error) {
	if len(r.List) == 0 {
		return nil, errors.New("Got an empty roster list")
	}
	dst := r.List[0]
	req := &ExecPlanRequest{
		Genesis:  genesis,
		Workflow: wf,
	}
	reply := &ExecPlanReply{}
	err := c.SendProtobuf(dst, req, reply)
	return reply, err
}

func (c *Client) LogSkipchain(r *onet.Roster, genesis []byte) error {
	if len(r.List) == 0 {
		return errors.New("Got an empty roster list")
	}
	dst := r.List[0]
	req := &LogSkipchainRequest{
		Genesis: genesis,
	}
	reply := &LogSkipchainReply{}
	err := c.SendProtobuf(dst, req, reply)
	return err
}
