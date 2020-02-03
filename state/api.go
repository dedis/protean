package state

import (
	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

type Client struct {
	*onet.Client
	roster *onet.Roster
}

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit(cfg *sys.UnitConfig) (*InitUnitReply, error) {
	req := &InitUnitRequest{Cfg: cfg}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) SpawnDarc(spawnDarc darc.Darc, wait int, ed *sys.ExecutionData) (*SpawnDarcReply, error) {
	req := &SpawnDarcRequest{
		Darc:     spawnDarc,
		Wait:     wait,
		ExecData: ed,
	}
	reply := &SpawnDarcReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

// This is called by the organize/owner/admin of the application
func (c *Client) CreateState(contractID string, kv []*KV, adminDarc darc.Darc, signerCtr uint64, signer darc.Signer, wait int, ed *sys.ExecutionData) (*CreateStateReply, error) {
	args := make(byzcoin.Arguments, len(kv))
	for i, elt := range kv {
		args[i] = byzcoin.Argument{Name: elt.Key, Value: elt.Value}
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion, byzcoin.Instruction{
		InstanceID: byzcoin.NewInstanceID(adminDarc.GetBaseID()),
		Spawn: &byzcoin.Spawn{
			ContractID: contractID,
			Args:       args,
		},
		SignerCounter: []uint64{signerCtr},
	})
	err := ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	req := &CreateStateRequest{
		Ctx:      ctx,
		Wait:     wait,
		ExecData: ed,
	}
	reply := &CreateStateReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) UpdateState(contractID string, cmd string, instID byzcoin.InstanceID, kv []*KV, signer darc.Signer, signerCtr uint64, wait int, ed *sys.ExecutionData) (*UpdateStateReply, error) {
	log.Info("In UpdateState:", contractID, cmd, instID.String(), signer.Identity().String())
	args := make(byzcoin.Arguments, len(kv))
	for i, elt := range kv {
		args[i] = byzcoin.Argument{Name: elt.Key, Value: elt.Value}
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion, byzcoin.Instruction{
		InstanceID: instID,
		Invoke: &byzcoin.Invoke{
			ContractID: contractID,
			Command:    cmd,
			Args:       args,
		},
		SignerCounter: []uint64{signerCtr},
	})
	err := ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	req := &UpdateStateRequest{
		Ctx:      ctx,
		Wait:     wait,
		ExecData: ed,
	}
	reply := &UpdateStateReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) GetProof(instID byzcoin.InstanceID, ed *sys.ExecutionData) (*GetProofReply, error) {
	req := &GetProofRequest{
		InstanceID: instID,
		ExecData:   ed,
	}
	reply := &GetProofReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func GetServiceID() onet.ServiceID {
//return stateID
//}
