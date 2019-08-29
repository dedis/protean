package pristore

import (
	"time"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"

	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

type Client struct {
	*onet.Client
	roster   *onet.Roster
	ltsReply *calypso.CreateLTSReply
}

func NewClient() *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName)}
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

func (c *Client) Authorize(who *network.ServerIdentity, id skipchain.SkipBlockID) error {
	req := &AuthorizeRequest{
		Request: &calypso.Authorise{
			ByzCoinID: id,
		},
	}
	reply := &AuthorizeReply{}
	err := c.SendProtobuf(who, req, reply)
	return err
}

func (c *Client) CreateLTS(ltsRoster *onet.Roster, wait int) error {
	req := &CreateLTSRequest{
		LTSRoster: ltsRoster,
		Wait:      wait,
	}
	reply := &CreateLTSReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	if err == nil {
		c.ltsReply = reply.Reply
	}
	return err
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

func (c *Client) AddWrite(data []byte, signer darc.Signer, signerCtr uint64, darc darc.Darc, wait int) (*AddWriteReply, error) {
	write := calypso.NewWrite(cothority.Suite, c.ltsReply.InstanceID, darc.GetBaseID(), c.ltsReply.X, data)
	writeBuf, err := protobuf.Encode(write)
	if err != nil {
		return nil, err
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: byzcoin.Instructions{{
			InstanceID: byzcoin.NewInstanceID(darc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: calypso.ContractWriteID,
				Args: byzcoin.Arguments{{
					Name: "write", Value: writeBuf}},
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	req := &AddWriteRequest{
		Ctx:  ctx,
		Wait: wait,
	}
	reply := &AddWriteReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) AddRead(proof *byzcoin.Proof, signer darc.Signer, signerCtr uint64, wait int) (*AddReadReply, error) {
	instID := proof.InclusionProof.Key()
	read := &calypso.Read{
		Write: byzcoin.NewInstanceID(instID),
		Xc:    signer.Ed25519.Point,
	}
	readBuf, err := protobuf.Encode(read)
	if err != nil {
		log.Errorf("Protobuf encode error: %v", err)
		return nil, err
	}
	log.Infof("In AddRead sending txn to %s contract", calypso.ContractReadID)
	ctx := byzcoin.ClientTransaction{
		Instructions: byzcoin.Instructions{{
			InstanceID: byzcoin.NewInstanceID(instID),
			Spawn: &byzcoin.Spawn{
				ContractID: calypso.ContractReadID,
				Args:       byzcoin.Arguments{{Name: "read", Value: readBuf}},
			},
			SignerCounter: []uint64{signerCtr},
		}},
	}
	err = ctx.FillSignersAndSignWith(signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	req := &AddReadRequest{
		Ctx:  ctx,
		Wait: wait,
	}
	reply := &AddReadReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Decrypt(wrProof byzcoin.Proof, rProof byzcoin.Proof) (*DecryptReply, error) {
	req := &DecryptRequest{
		Request: &calypso.DecryptKey{
			Read:  rProof,
			Write: wrProof,
		},
	}
	reply := &DecryptReply{}
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

func (dkr *DecryptReply) RecoverKey(reader darc.Signer) ([]byte, error) {
	return dkr.Reply.RecoverKey(reader.Ed25519.Secret)
}

func CreateDarc(ownerID darc.Identity, name string) *darc.Darc {
	return darc.NewDarc(darc.InitRules([]darc.Identity{ownerID}, []darc.Identity{ownerID}), []byte(name))
}

func AddWriteRule(d *darc.Darc, writers ...darc.Signer) error {
	//var ids []string
	ids := make([]string, len(writers))
	for i, w := range writers {
		//ids = append(ids, w.Identity().String())
		ids[i] = w.Identity().String()
	}
	return d.Rules.AddRule(darc.Action("spawn:"+calypso.ContractWriteID), expression.InitOrExpr(ids...))
}

func AddReadRule(d *darc.Darc, readers ...darc.Signer) error {
	//var ids []string
	ids := make([]string, len(readers))
	for i, r := range readers {
		//ids = append(ids, r.Identity().String())
		ids[i] = r.Identity().String()
	}
	return d.Rules.AddRule(darc.Action("spawn:"+calypso.ContractReadID), expression.InitOrExpr(ids...))
}
