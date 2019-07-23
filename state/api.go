package state

import (
	"fmt"
	"time"

	"github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	//"go.dedis.ch/onet/v3/log"
	//"go.dedis.ch/onet/v3/network"
	//"go.dedis.ch/protobuf"
)

type Client struct {
	*onet.Client
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
}

func (c *Client) UpdateState(r *onet.Roster, kv []*KV, instID byzcoin.InstanceID, signerCtr uint64, signer darc.Signer, wait int) (*UpdateStateReply, error) {
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	var args byzcoin.Arguments
	for _, elt := range kv {
		args = append(args, byzcoin.Argument{Name: elt.Key, Value: elt.Value})
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: instID,
			Invoke: &byzcoin.Invoke{
				ContractID: ContractKeyValueID,
				Command:    "update",
				Args:       args,
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
	err := ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Signing the transaction failed: %v", err)
		return nil, err
	}
	req := &UpdateStateRequest{
		Ctx:  ctx,
		Wait: wait,
	}
	reply := &UpdateStateReply{}
	err = c.SendProtobuf(dst, req, reply)
	return reply, err
}

// This is called by the organize/owner/admin of the application
func (c *Client) CreateState(r *onet.Roster, kv []*KV, adminDarc darc.Darc, signerCtr uint64, signer darc.Signer, wait int) (*CreateStateReply, error) {
	reply := &CreateStateReply{}
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	var args byzcoin.Arguments
	for _, elt := range kv {
		args = append(args, byzcoin.Argument{Name: elt.Key, Value: elt.Value})
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(adminDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: ContractKeyValueID,
				Args:       args,
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
	err := ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Signing the transaction failed: %v", err)
		return nil, err
	}
	req := &CreateStateRequest{
		Ctx:  ctx,
		Wait: wait,
	}
	err = c.SendProtobuf(dst, req, reply)
	return reply, err
}

func (c *Client) SpawnDarc(r *onet.Roster, spawnDarc darc.Darc, wait int) (*SpawnDarcReply, error) {
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	req := &SpawnDarcRequest{
		Darc: spawnDarc,
		Wait: wait,
	}
	reply := &SpawnDarcReply{}
	err := c.SendProtobuf(dst, req, reply)
	return nil, err
}

//func (c *Client) InitUnitRequest(r *onet.Roster, uid string, txns map[string]string, publics []kyber.Point) error {
func (c *Client) InitUnit(r *onet.Roster, scData *utils.ScInitData, unitData *protean.UnitStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	req := &InitUnitRequest{
		ScData:       scData,
		UnitData:     unitData,
		BlkInterval:  interval,
		DurationType: typeDur,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(dst, req, reply)
	return reply, err
}

func (c *Client) GetProof(r *onet.Roster, instID []byte) (*GetProofReply, error) {
	if len(r.List) == 0 {
		return nil, fmt.Errorf("Got an empty roster list")
	}
	dst := r.List[0]
	req := &GetProofRequest{
		InstID: instID,
	}
	reply := &GetProofReply{}
	err := c.SendProtobuf(dst, req, reply)
	return reply, err
}
