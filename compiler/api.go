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

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) InitUnit(roster *onet.Roster, scData *protean.ScInitData) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Roster: roster,
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
