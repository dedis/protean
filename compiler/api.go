package compiler

import (
	"fmt"

	"github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) InitUnit(r *onet.Roster, scData *utils.ScInitData) (*InitUnitReply, error) {
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	req := &InitUnitRequest{
		ScData: scData,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(dst, req, reply)
	return reply, err
}

func (c *Client) CreateUnits(r *onet.Roster, genesis []byte, units []*FunctionalUnit) (*CreateUnitsReply, error) {
	//TODO: Check values in struct?
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
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

func (c *Client) GenerateExecutionPlan(r *onet.Roster, genesis []byte, wf []*protean.WfNode) (*ExecutionPlanReply, error) {
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	req := &ExecutionPlanRequest{
		Genesis:  genesis,
		Workflow: wf,
	}
	reply := &ExecutionPlanReply{}
	err := c.SendProtobuf(dst, req, reply)
	if err != nil {
		return nil, err
	}
	return reply, err
}

func (c *Client) LogSkipchain(r *onet.Roster, genesis []byte) error {
	if len(r.List) == 0 {
		return fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	req := &LogSkipchainRequest{
		Genesis: genesis,
	}
	reply := &LogSkipchainReply{}
	err := c.SendProtobuf(dst, req, reply)
	return err
}
