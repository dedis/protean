package pristore

import (
	"github.com/ceyhunalp/protean_code/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

var ServiceName = "PrivStoreService"
var privStoreID onet.ServiceID

type Service struct {
	*onet.ServiceProcessor
	scService   *skipchain.Service
	byzService  *byzcoin.Service
	calyService *calypso.Service
	cosiService *blscosi.Service

	roster    *onet.Roster
	genesis   skipchain.SkipBlockID
	gMsg      *byzcoin.CreateGenesisBlock
	byzID     skipchain.SkipBlockID
	signer    darc.Signer
	signerCtr uint64
}

func init() {
	var err error
	privStoreID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&AuthorizeRequest{}, &AuthorizeReply{}, &CreateLTSRequest{},
		&CreateLTSReply{}, &SpawnDarcRequest{}, &SpawnDarcReply{},
		&AddWriteRequest{}, &AddWriteReply{}, &AddReadRequest{},
		&AddReadReply{}, &DecryptRequest{}, &DecryptReply{}, &GetProofRequest{}, &GetProofReply{})
}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	// Creating the skipchain here
	log.Infof("Starting InitUnit")
	genesisReply, err := utils.CreateGenesisBlock(s.scService, req.ScData)
	if err != nil {
		return nil, err
	}
	s.genesis = genesisReply.Latest.Hash
	s.roster = req.ScData.Roster
	///////////////////////
	// Now adding a block with the unit information
	enc, err := protobuf.Encode(req.BaseStore)
	if err != nil {
		log.Errorf("Error in protobuf encoding: %v", err)
		return nil, err
	}
	err = utils.StoreBlock(s.scService, s.genesis, enc)
	if err != nil {
		log.Errorf("Cannot add block to skipchain: %v", err)
		return nil, err
	}
	/////// Now setup byzcoin //////
	s.signer = darc.NewSignerEd25519(nil, nil)
	s.signerCtr = uint64(1)
	s.gMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, s.roster, []string{"spawn:" + calypso.ContractLongTermSecretID}, s.signer.Identity())
	if err != nil {
		log.Errorf("Cannot create the default genesis message for Byzcoin: %v", err)
		return nil, err
	}
	s.gMsg.BlockInterval = req.BlkInterval * req.DurationType
	resp, err := s.byzService.CreateGenesisBlock(s.gMsg)
	if err != nil {
		log.Errorf("Cannot create the genesis block for Byzcoin: %v", err)
		return nil, err
	}
	s.byzID = resp.Skipblock.CalculateHash()
	return &InitUnitReply{Genesis: s.genesis, ID: s.byzID}, nil
}

func (s *Service) Authorize(req *AuthorizeRequest) (*AuthorizeReply, error) {
	var err error
	reply := &AuthorizeReply{}
	reply.Reply, err = s.calyService.Authorise(req.Request)
	if err != nil {
		log.Errorf("Authorize error: %v", err)
		return nil, err
	}
	return reply, nil
}

func (s *Service) CreateLTS(req *CreateLTSRequest) (*CreateLTSReply, error) {
	buf, err := protobuf.Encode(&calypso.LtsInstanceInfo{Roster: *req.LTSRoster})
	if err != nil {
		log.Errorf("Protobuf encode error: %v", err)
		return nil, err
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(s.gMsg.GenesisDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: calypso.ContractLongTermSecretID,
				Args: []byzcoin.Argument{
					{Name: "lts_instance_info", Value: buf},
				},
			},
			SignerCounter: []uint64{s.signerCtr},
		}},
	}
	err = ctx.FillSignersAndSignWith(s.signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	_, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Cannot create LTS -- Byzcoin add transaction error: %v", err)
		return nil, err
	}
	gpResp, err := s.byzService.GetProof(&byzcoin.GetProof{
		Version: byzcoin.CurrentVersion,
		ID:      s.byzID,
		Key:     ctx.Instructions[0].DeriveID("").Slice(),
	})
	reply := &CreateLTSReply{}
	reply.Reply, err = s.calyService.CreateLTS(&calypso.CreateLTS{
		Proof: gpResp.Proof,
	})
	if err != nil {
		log.Errorf("CreateLTS error: %v", err)
		return nil, err
	}
	s.signerCtr++
	return reply, nil
}

func (s *Service) SpawnDarc(req *SpawnDarcRequest) (*SpawnDarcReply, error) {
	darcBuf, err := req.Darc.ToProto()
	if err != nil {
		log.Errorf("Cannot convert darc to protobuf: %v", err)
		return nil, err
	}
	ctx := byzcoin.ClientTransaction{
		Instructions: []byzcoin.Instruction{{
			InstanceID: byzcoin.NewInstanceID(s.gMsg.GenesisDarc.GetBaseID()),
			Spawn: &byzcoin.Spawn{
				ContractID: byzcoin.ContractDarcID,
				Args: []byzcoin.Argument{{
					Name:  "darc",
					Value: darcBuf,
				}},
			},
			SignerCounter: []uint64{s.signerCtr},
		}},
	}
	err = ctx.FillSignersAndSignWith(s.signer)
	if err != nil {
		log.Errorf("Sign transaction failed: %v", err)
		return nil, err
	}
	_, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Add transaction failed: %v", err)
		return nil, err
	}
	s.signerCtr++
	return &SpawnDarcReply{}, nil
}

func (s *Service) AddWrite(req *AddWriteRequest) (*AddWriteReply, error) {
	_, err := s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Cannot add write -- Byzcoin add transaction error: %v", err)
		return nil, err
	}
	return &AddWriteReply{InstanceID: req.Ctx.Instructions[0].DeriveID("")}, nil
}

func (s *Service) AddRead(req *AddReadRequest) (*AddReadReply, error) {
	_, err := s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Cannot add read -- Byzcoin add transaction error: %v", err)
		return nil, err
	}
	return &AddReadReply{InstanceID: req.Ctx.Instructions[0].DeriveID("")}, nil
}

func (s *Service) Decrypt(req *DecryptRequest) (*DecryptReply, error) {
	var err error
	reply := &DecryptReply{}
	reply.Reply, err = s.calyService.DecryptKey(req.Request)
	if err != nil {
		log.Errorf("Decrypt error: %v", err)
		return nil, err
	}
	return reply, nil
}

func (s *Service) GetProof(req *GetProofRequest) (*GetProofReply, error) {
	var err error
	reply := &GetProofReply{}
	reply.GetProofResponse, err = s.byzService.GetProof(&byzcoin.GetProof{
		Version: byzcoin.CurrentVersion,
		ID:      s.byzID,
		Key:     req.InstanceID.Slice(),
	})
	if err != nil {
		log.Errorf("GetProof request failed: %v", err)
		return nil, err
	}
	return reply, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
		byzService:       c.Service(byzcoin.ServiceName).(*byzcoin.Service),
		calyService:      c.Service(calypso.ServiceName).(*calypso.Service),
		cosiService:      c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	err := s.RegisterHandlers(s.InitUnit, s.Authorize, s.CreateLTS, s.SpawnDarc, s.AddWrite, s.AddRead, s.Decrypt, s.GetProof)
	if err != nil {
		log.Errorf("Cannot register handlers: %v", err)
		return nil, err
	}
	return s, nil
}
