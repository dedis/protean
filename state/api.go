package state

import (
	"time"

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

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) UpdateState(contractID string, kv []*KV, instID byzcoin.InstanceID, signerCtr uint64, signer darc.Signer, wait int) (*UpdateStateReply, error) {
	//var args byzcoin.Arguments
	//for _, elt := range kv {
	//args = append(args, byzcoin.Argument{Name: elt.Key, Value: elt.Value})
	//}
	args := make(byzcoin.Arguments, len(kv))
	for i, elt := range kv {
		args[i] = byzcoin.Argument{Name: elt.Key, Value: elt.Value}
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: instID,
			Invoke: &byzcoin.Invoke{
				ContractID: contractID,
				Command:    "update",
				Args:       args,
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
	err := ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	req := &UpdateStateRequest{
		Ctx:  ctx,
		Wait: wait,
	}
	reply := &UpdateStateReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

// This is called by the organize/owner/admin of the application
func (c *Client) CreateState(contractID string, kv []*KV, adminDarc darc.Darc, signerCtr uint64, signer darc.Signer, wait int) (*CreateStateReply, error) {
	//var args byzcoin.Arguments
	//for _, elt := range kv {
	//args = append(args, byzcoin.Argument{Name: elt.Key, Value: elt.Value})
	//}
	args := make(byzcoin.Arguments, len(kv))
	for i, elt := range kv {
		args[i] = byzcoin.Argument{Name: elt.Key, Value: elt.Value}
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(adminDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: contractID,
				Args:       args,
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
	err := ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	req := &CreateStateRequest{
		Ctx:  ctx,
		Wait: wait,
	}
	reply := &CreateStateReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) SpawnDarc(spawnDarc darc.Darc, wait int) (*SpawnDarcReply, error) {
	req := &SpawnDarcRequest{
		Darc: spawnDarc,
		Wait: wait,
	}
	reply := &SpawnDarcReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

//func (c *Client) InitUnit(roster *onet.Roster, scData *sys.ScInitData, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
func (c *Client) InitUnit(roster *onet.Roster, scCfg *sys.ScConfig, bStore *sys.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	c.roster = roster
	req := &InitUnitRequest{
		Cfg: &sys.UnitConfig{
			Roster:       roster,
			ScCfg:        scCfg,
			BaseStore:    bStore,
			BlkInterval:  interval,
			DurationType: typeDur,
		},
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) GetProof(instID byzcoin.InstanceID) (*GetProofReply, error) {
	req := &GetProofRequest{
		InstanceID: instID,
	}
	reply := &GetProofReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
