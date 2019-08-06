package compiler

import (
	"github.com/dedis/protean"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit(scData *protean.ScInitData) (*InitUnitReply, error) {
	req := &InitUnitRequest{
		ScData: scData,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) CreateUnits(genesis []byte, units []*FunctionalUnit) (*CreateUnitsReply, error) {
	//TODO: Check values in struct?
	req := &CreateUnitsRequest{
		Genesis: genesis,
		Units:   units,
	}
	reply := &CreateUnitsReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) GenerateExecutionPlan(genesis []byte, wf []*protean.WfNode) (*ExecutionPlanReply, error) {
	req := &ExecutionPlanRequest{
		Genesis:  genesis,
		Workflow: wf,
	}
	reply := &ExecutionPlanReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) LogSkipchain(genesis []byte) error {
	req := &LogSkipchainRequest{
		Genesis: genesis,
	}
	reply := &LogSkipchainReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return err
}
