package pristore

import (
	"fmt"

	"github.com/dedis/protean/sys"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/darc/expression"
	"go.dedis.ch/kyber/v3"

	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
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

func (c *Client) CreateLTS(ltsRoster *onet.Roster, wait int, ed *sys.ExecutionData) (*CreateLTSReply, error) {
	req := &CreateLTSRequest{
		LTSRoster: ltsRoster,
		Wait:      wait,
		ExecData:  ed,
	}
	reply := &CreateLTSReply{}
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

func (c *Client) AddWrite(data []byte, ltsID byzcoin.InstanceID, X kyber.Point, signer darc.Signer, signerCtr uint64, darc darc.Darc, wait int, ed *sys.ExecutionData) (*AddWriteReply, error) {
	write := calypso.NewWrite(cothority.Suite, ltsID, darc.GetBaseID(), X, data)
	if write == nil {
		log.Errorf("Cannot create Calypso write")
		return nil, fmt.Errorf("Cannot create Calypso write")
	}
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
		Ctx:      ctx,
		Wait:     wait,
		ExecData: ed,
	}
	reply := &AddWriteReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) AddRead(proof *byzcoin.Proof, signer darc.Signer, signerCtr uint64, wait int, ed *sys.ExecutionData) (*AddReadReply, error) {
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
		Ctx:      ctx,
		Wait:     wait,
		ExecData: ed,
	}
	reply := &AddReadReply{}
	err = c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) AddReadBatch(proofs []*byzcoin.Proof, signer darc.Signer, signerCtr uint64, wait int, ed *sys.ExecutionData) (*AddReadBatchReply, error) {
	ctxs := make([]byzcoin.ClientTransaction, len(proofs))
	for i, p := range proofs {
		// Create a read transaction only if the write proof is
		// available
		if p != nil {
			instID := p.InclusionProof.Key()
			read := &calypso.Read{
				Write: byzcoin.NewInstanceID(instID),
				Xc:    signer.Ed25519.Point,
			}
			readBuf, err := protobuf.Encode(read)
			if err != nil {
				log.Errorf("Protobuf encode error: %v", err)
				return nil, err
			}
			ctxs[i] = byzcoin.ClientTransaction{
				Instructions: byzcoin.Instructions{{
					InstanceID: byzcoin.NewInstanceID(instID),
					Spawn: &byzcoin.Spawn{
						ContractID: calypso.ContractReadID,
						Args:       byzcoin.Arguments{{Name: "read", Value: readBuf}},
					},
					SignerCounter: []uint64{signerCtr},
				}},
			}
			err = ctxs[i].FillSignersAndSignWith(signer)
			if err != nil {
				log.Errorf("Sign transaction failed: %v", err)
				return nil, err
			}
			signerCtr++
		}
	}
	req := &AddReadBatchRequest{
		Ctxs:     ctxs,
		Wait:     wait,
		ExecData: ed,
	}
	reply := &AddReadBatchReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
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

func (c *Client) GetProofBatch(iidBatch []*IID, ed *sys.ExecutionData) (*GetProofBatchReply, error) {
	req := &GetProofBatchRequest{
		IIDBatch: iidBatch,
		ExecData: ed,
	}
	reply := &GetProofBatchReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) Decrypt(wrProof *byzcoin.Proof, rProof *byzcoin.Proof, ed *sys.ExecutionData) (*DecryptReply, error) {
	req := &DecryptRequest{
		Request: &calypso.DecryptKey{
			Read:  *rProof,
			Write: *wrProof,
		},
		ExecData: ed,
	}
	reply := &DecryptReply{}
	err := c.SendProtobuf(c.roster.List[0], req, reply)
	return reply, err
}

func (c *Client) DecryptBatch(wrProofs []*byzcoin.Proof, rProofs []*byzcoin.Proof, ed *sys.ExecutionData) (*DecryptBatchReply, error) {
	if len(wrProofs) != len(rProofs) {
		return nil, fmt.Errorf("Number of write proofs does not match the number of read proofs")
	}
	sz := len(wrProofs)
	dks := make([]*calypso.DecryptKey, sz)
	for i := 0; i < sz; i++ {
		dks[i] = &calypso.DecryptKey{
			Read:  *rProofs[i],
			Write: *wrProofs[i],
		}
	}
	req := &DecryptBatchRequest{Requests: dks, ExecData: ed}
	reply := &DecryptBatchReply{}
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
	ids := make([]string, len(writers))
	for i, w := range writers {
		ids[i] = w.Identity().String()
	}
	return d.Rules.AddRule(darc.Action("spawn:"+calypso.ContractWriteID), expression.InitOrExpr(ids...))
}

func AddReadRule(d *darc.Darc, readers ...darc.Signer) error {
	ids := make([]string, len(readers))
	for i, r := range readers {
		ids[i] = r.Identity().String()
	}
	return d.Rules.AddRule(darc.Action("spawn:"+calypso.ContractReadID), expression.InitOrExpr(ids...))
}

func GetServiceID() onet.ServiceID {
	return priStoreID
}
