package dummy

import (
	//"crypto/sha256"
	//"errors"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/protobuf"

	//"go.dedis.ch/kyber/v3/pairing"
	//"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	//"go.dedis.ch/protobuf"
)

//var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)
var ServiceName = "DummyService"
var dummyID onet.ServiceID

type Service struct {
	*onet.ServiceProcessor
	byzService *byzcoin.Service
	scService  *skipchain.Service

	roster    *onet.Roster
	genesis   skipchain.SkipBlockID
	byzID     skipchain.SkipBlockID
	gMsg      *byzcoin.CreateGenesisBlock
	signer    darc.Signer
	signerCtr uint64
}

func init() {
	var err error
	dummyID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&SpawnDarcRequest{}, &SpawnDarcReply{}, &CreateStateRequest{},
		&CreateStateReply{}, &GetProofRequest{}, &GetProofReply{},
		&UpdateStateRequest{}, &UpdateStateReply{}, &InitByzcoinRequest{},
		&InitByzcoinReply{}, &StoreRequest{}, &StoreReply{})
}

func (s *Service) UpdateState(req *UpdateStateRequest) (*UpdateStateReply, error) {
	//TODO: Do the same stuff as above in UpdateState
	//Handle the byzcoin part
	_, err := s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Add transaction failed: %v", err)
		return nil, err
	}
	return &UpdateStateReply{}, nil
}

func (s *Service) CreateState(req *CreateStateRequest) (*CreateStateReply, error) {
	//TODO: Do the same stuff as above in UpdateState
	//Handle the byzcoin part
	reply := &CreateStateReply{}
	reply.InstanceID = req.Ctx.Instructions[0].DeriveID("")
	_, err := s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Add transaction failed: %v", err)
		return nil, err
	}
	return reply, nil
}

func (s *Service) SpawnDarc(req *SpawnDarcRequest) (*SpawnDarcReply, error) {
	darcBuf, err := req.Darc.ToProto()
	if err != nil {
		log.Errorf("Cannot convert darc to protobuf: %v", err)
		return nil, err
	}
	ctx := byzcoin.NewClientTransaction(byzcoin.CurrentVersion, byzcoin.Instruction{
		InstanceID: byzcoin.NewInstanceID(s.gMsg.GenesisDarc.GetBaseID()),
		Spawn: &byzcoin.Spawn{
			ContractID: byzcoin.ContractDarcID,
			Args: []byzcoin.Argument{{
				Name:  "darc",
				Value: darcBuf,
			}},
		},
		SignerCounter: []uint64{s.signerCtr},
	})
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

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	// Creating the skipchain here
	cfg := req.Cfg
	genesisReply, err := utils.CreateGenesisBlock(s.scService, cfg.ScCfg, cfg.Roster)
	if err != nil {
		return nil, err
	}
	s.genesis = genesisReply.Latest.Hash
	s.roster = cfg.Roster
	///////////////////////
	// Now adding a block with the unit information
	enc, err := protobuf.Encode(cfg.BaseStore)
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
	s.gMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, s.roster, []string{"spawn:" + ContractKeyValueID, "invoke:" + ContractKeyValueID}, s.signer.Identity())
	if err != nil {
		log.Errorf("Cannot create the default genesis message for Byzcoin: %v", err)
		return nil, err
	}
	s.gMsg.BlockInterval = cfg.BlkInterval * cfg.DurationType
	resp, err := s.byzService.CreateGenesisBlock(s.gMsg)
	if err != nil {
		log.Errorf("Cannot create the genesis block for Byzcoin: %v", err)
		return nil, err
	}
	s.byzID = resp.Skipblock.CalculateHash()
	return &InitUnitReply{Genesis: s.genesis}, nil
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

func (s *Service) StoreGenesis(req *StoreRequest) (*StoreReply, error) {
	s.genesis = req.Genesis
	return nil, nil
}

func (s *Service) InitByzcoin(req *InitByzcoinRequest) (*InitByzcoinReply, error) {
	var err error
	s.roster = req.Roster
	s.signer = darc.NewSignerEd25519(nil, nil)
	s.signerCtr = uint64(1)
	s.gMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, s.roster, []string{"spawn:" + ContractKeyValueID, "invoke:" + ContractKeyValueID}, s.signer.Identity())
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
	return &InitByzcoinReply{}, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		byzService:       c.Service(byzcoin.ServiceName).(*byzcoin.Service),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
	}
	err := s.RegisterHandlers(s.InitUnit, s.InitByzcoin, s.SpawnDarc, s.CreateState, s.UpdateState, s.GetProof, s.StoreGenesis)
	if err != nil {
		log.Errorf("Cannot register handlers: %v", err)
		return nil, err
	}
	err = byzcoin.RegisterContract(c, ContractKeyValueID, contractValueFromBytes)
	if err != nil {
		log.Errorf("Cannot register contract %s: %v", ContractKeyValueID, err)
		return nil, err
	}
	err = byzcoin.RegisterContract(c, ContractLotteryID, contractLotteryFromBytes)
	if err != nil {
		log.Errorf("Cannot register contract %s: %v", ContractLotteryID, err)
		return nil, err
	}
	return s, nil
}
