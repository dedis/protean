package pristore

import (
	"time"

	protean "github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"

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

func NewClient(r *onet.Roster) *Client {
	return &Client{Client: onet.NewClient(cothority.Suite, ServiceName), roster: r}
}

func (c *Client) InitUnit(scData *utils.ScInitData, bStore *protean.BaseStorage, interval time.Duration, typeDur time.Duration) (*InitUnitReply, error) {
	req := &InitUnitRequest{
		ScData:       scData,
		BaseStore:    bStore,
		BlkInterval:  interval,
		DurationType: typeDur,
	}
	reply := &InitUnitReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Authorize(who *network.ServerIdentity, id skipchain.SkipBlockID) error {
	reply := &AuthorizeReply{}
	req := &AuthorizeRequest{
		Request: &calypso.Authorise{
			ByzCoinID: id,
		},
	}
	err := c.SendProtobuf(who, req, reply)
	return err
}

//func (c *Client) CreateLTS(ltsRoster *onet.Roster, darcID darc.ID, signers []darc.Signer, counters []uint64, wait int) (*CreateLTSReply, error) {
func (c *Client) CreateLTS(ltsRoster *onet.Roster, wait int) error {
	//buf, err := protobuf.Encode(&calypso.LtsInstanceInfo{Roster: *ltsRoster})
	//if err != nil {
	//log.Errorf("Protobuf encode error: %v", err)
	//return nil, err
	//}
	//ctx := byzcoin.ClientTransaction{
	//Instructions: []byzcoin.Instruction{{
	//InstanceID: byzcoin.NewInstanceID(darcID),
	//Spawn: &byzcoin.Spawn{
	//ContractID: calypso.ContractLongTermSecretID,
	//Args: []byzcoin.Argument{
	//{Name: "lts_instance_info", Value: buf},
	//},
	//},
	//SignerCounter: counters,
	//}},
	//}
	//err = ctx.FillSignersAndSignWith(signers...)
	//if err != nil {
	//log.Errorf("Sign transaction failed: %v", err)
	//return nil, err
	//}
	req := &CreateLTSRequest{
		//Ctx:  ctx,
		LTSRoster: ltsRoster,
		Wait:      wait,
	}
	reply := &CreateLTSReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	//TODO: This check might be unnecessary
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

//func (c *Client) AddWrite(wd *WriteData, signer darc.Signer, signerCtr uint64, darc darc.Darc, wait int) (*AddWriteReply, error) {
//func (c *Client) AddWrite(writeDarc darc.ID, data []byte, signer darc.Signer, signerCtr uint64, darc darc.Darc, wait int) (*AddWriteReply, error) {
func (c *Client) AddWrite(data []byte, signer darc.Signer, signerCtr uint64, darc darc.Darc, wait int) (*AddWriteReply, error) {
	reply := &AddWriteReply{}
	//write := calypso.NewWrite(cothority.Suite, wd.ltsID, wd.writeDarc, wd.aggKey, wd.data)
	//write := calypso.NewWrite(cothority.Suite, c.ltsReply.InstanceID, writeDarc, c.ltsReply.X, data)
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
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	//if err != nil {
	//reply.InstanceID = ctx.Instructions[0].DeriveID("")
	//}
	return reply, err
}

//func (c *Client) AddRead(proof *byzcoin.Proof, signer darc.Signer, signerCtr uint64, darc darc.Darc, wait int) (*AddReadReply, error) {
func (c *Client) AddRead(proof *byzcoin.Proof, signer darc.Signer, signerCtr uint64, wait int) (*AddReadReply, error) {
	reply := &AddReadReply{}
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
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	//if err != nil {
	//reply.InstanceID = ctx.Instructions[0].DeriveID("")
	//}
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

//func (c *Client) DecodeKey(dkr *DecryptReply, reader darc.Signer) ([]byte, error) {
//return calypso.DecodeKey(cothority.Suite, c.ltsReply.X, dkr.Reply.C, dkr.Reply.XhatEnc, reader.Ed25519.Secret)
//}
func (c *Client) RecoverKey(dkr *DecryptReply, reader darc.Signer) ([]byte, error) {
	return dkr.Reply.RecoverKey(reader.Ed25519.Secret)
}

func (c *Client) GetProof(instID byzcoin.InstanceID) (*GetProofReply, error) {
	req := &GetProofRequest{
		InstanceID: instID,
	}
	reply := &GetProofReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}
