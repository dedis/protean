package dummy

import (
	//"crypto/sha256"
	//"errors"
	"fmt"
	//"github.com/ceyhunalp/protean_code"
	//"github.com/ceyhunalp/protean_code/verify"
	//"go.dedis.ch/cothority/v3/blscosi"
	"github.com/ceyhunalp/protean_code/utils"
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

// This service is only used because we need to register our contracts to
// the ByzCoin service. So we create this stub and add contracts to it
// from the `contracts` directory.

//var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)

var ServiceName = "DummyService"
var dummyID onet.ServiceID

// Service is only used to being able to store our contracts
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	roster    *onet.Roster
	genesis   skipchain.SkipBlockID
	byzID     skipchain.SkipBlockID
	gMsg      *byzcoin.CreateGenesisBlock
	signer    darc.Signer
	signerCtr uint64

	scService  *skipchain.Service
	byzService *byzcoin.Service
}

func init() {
	var err error
	dummyID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	//TODO:Check the error message here
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&SpawnDarcRequest{}, &SpawnDarcReply{}, &CreateStateRequest{},
		&CreateStateReply{}, &GetProofRequest{}, &GetProofReply{},
		&UpdateStateRequest{}, &UpdateStateReply{})
}

//TODO: Update state probably needs to return something more than an error.
//Maybe something about the state update? (e.g. proof?)
//func (s *Service) UpdateState(req *UpdateStateRequest) (*UpdateStateReply, error) {
////Now you can do the actual FU-related stuff

//return nil, nil
//}

func (s *Service) UpdateState(req *UpdateStateRequest) (*UpdateStateReply, error) {
	//TODO: Do the same stuff as above in UpdateState
	//Handle the byzcoin part
	var err error
	reply := &UpdateStateReply{}
	reply.AddTxResp, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("update state: add transaction failed: %v", err)
		return nil, err
	}
	//reply.InstID = req.Ctx.Instructions[0].DeriveID("")
	return reply, nil
}

func (s *Service) CreateState(req *CreateStateRequest) (*CreateStateReply, error) {
	//TODO: Do the same stuff as above in UpdateState
	//Handle the byzcoin part
	var err error
	reply := &CreateStateReply{}
	reply.AddTxResp, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("create state: add transaction failed: %v", err)
		return nil, err
	}
	reply.InstID = req.Ctx.Instructions[0].DeriveID("")
	return reply, nil
}

func (s *Service) SpawnDarc(req *SpawnDarcRequest) (*SpawnDarcReply, error) {
	darcBuf, err := req.Darc.ToProto()
	if err != nil {
		log.Errorf("Could not convert darc to protobuf: %v", err)
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
		log.Errorf("Transaction sign failed: %v", err)
		return nil, err
	}
	_, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Spawn darc: add transaction failed: %v", err)
		return nil, err
	}
	s.signerCtr++
	return &SpawnDarcReply{}, nil
}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	// Creating the skipchain here
	genesisReply, err := utils.CreateGenesisBlock(s.scService, req.ScData)
	if err != nil {
		return nil, err
	}
	s.genesis = genesisReply.Latest.Hash
	s.roster = req.ScData.Roster
	///////////////////////
	// Now adding a block with the unit information
	enc, err := protobuf.Encode(req.UnitData)
	if err != nil {
		log.Errorf("[InitUnit] Error in protobuf encoding: %v", err)
		return nil, err
	}
	err = utils.StoreBlock(s.scService, s.genesis, enc)
	if err != nil {
		return nil, err
	}
	/////// Now setup byzcoin //////
	//s.roster = req.Roster
	s.signer = darc.NewSignerEd25519(nil, nil)
	s.gMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, s.roster, []string{"spawn:" + ContractKeyValueID, "invoke:" + ContractKeyValueID}, s.signer.Identity())
	if err != nil {
		log.Errorf("[InitUnit] Could not create the default genesis message for Byzcoin: %v", err)
		return nil, err
	}
	s.gMsg.BlockInterval = req.BlkInterval * req.DurationType
	resp, err := s.byzService.CreateGenesisBlock(s.gMsg)
	if err != nil {
		log.Errorf("[InitUnit] Could not create the Byzcoin genesis block: %v", err)
		return nil, err
	}
	s.byzID = resp.Skipblock.SkipChainID()
	s.signerCtr = uint64(1)
	//s.gMsg = gMsg
	return &InitUnitReply{Genesis: genesisReply.Latest.Hash}, nil
}

func (s *Service) GetProof(req *GetProofRequest) (*GetProofReply, error) {
	var err error
	reply := &GetProofReply{}
	reply.GetProofResponse, err = s.byzService.GetProof(&byzcoin.GetProof{
		Version: byzcoin.CurrentVersion,
		ID:      s.byzID,
		Key:     req.InstID,
	})
	if err != nil {
		log.Errorf("get proof failed: %v", err)
		return nil, err
	}
	return reply, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		byzService:       c.Service(byzcoin.ServiceName).(*byzcoin.Service),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
	}
	//if err := s.RegisterHandlers(s.CreateState, s.UpdateState, s.InitUnit); err != nil {
	err := s.RegisterHandlers(s.InitUnit, s.SpawnDarc, s.CreateState, s.GetProof, s.UpdateState)
	if err != nil {
		return nil, fmt.Errorf("could not register handlers: %v", err)
	}
	err = byzcoin.RegisterContract(c, ContractKeyValueID, contractValueFromBytes)
	if err != nil {
		return nil, err
	}
	return s, nil
}
