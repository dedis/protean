package state

import (
	//"crypto/sha256"
	"errors"

	"github.com/ceyhunalp/protean_code/utils"
	//"github.com/ceyhunalp/protean_code"
	//"github.com/ceyhunalp/protean_code/verify"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	//"go.dedis.ch/kyber/v3/pairing"
	//"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

// This service is only used because we need to register our contracts to
// the ByzCoin service. So we create this stub and add contracts to it
// from the `contracts` directory.

//var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)

var ServiceName = "StateService"
var stateID onet.ServiceID

const proteanSubFtCosi = "protean_sub_ftcosi"
const proteanFtCosi = "protean_ftcosi"

// Service is only used to being able to store our contracts
type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	roster  *onet.Roster
	genesis skipchain.SkipBlockID
	byzID   skipchain.SkipBlockID
	gMsg    *byzcoin.CreateGenesisBlock
	signer  darc.Signer

	byzService  *byzcoin.Service
	cosiService *blscosi.Service
	scService   *skipchain.Service
}

func init() {
	var err error
	stateID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	//network.RegisterMessages(&CreateSkipchainRequest{},
	//&CreateSkipchainReply{}, &InitUnitRequest{}, &InitUnitReply{},
	//&CreateStateRequest{}, &CreateStateReply{})
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&CreateStateRequest{}, &CreateStateReply{}, &UpdateStateRequest{},
		&UpdateStateReply{}, &SpawnDarcRequest{}, &SpawnDarcReply{})
}

//TODO: Update state probably needs to return something more than an error.
//Maybe something about the state update? (e.g. proof?)
//func (s *Service) UpdateState(req *UpdateStateRequest) (*UpdateStateReply, error) {
//// Before we send Byzcoin transactions to update state, we need to make
//// sure that the execution plan has the necesssary signatures
//db := s.scService.GetDB()
//blk, err := db.GetLatest(db.GetByID(s.genesis))
//if err != nil {
//log.Errorf("Couldn't get the latest block: %v", err)
//return nil, err
//}
//tree := s.roster.GenerateNaryTreeWithRoot(len(s.roster.List), s.ServerIdentity())
//pi, err := s.CreateProtocol(verify.Name, tree)
//if err != nil {
//log.Errorf("Creating protocol failed: %v", err)
//return nil, err
//}
//verifyProto := pi.(*verify.VP)
//verifyProto.Block = blk
//verifyProto.Index = req.ExecData.Index
//verifyProto.ExecPlan = req.ExecData.ExecPlan
//verifyProto.PlanSig = req.ExecData.PlanSig
//verifyProto.SigMap = req.ExecData.SigMap
////verifyProto.FaultThreshold = req.FaultThreshold

//if !<-verifyProto.Verified {
//log.Lvl2("Execution plan verification success!")
//} else {
//log.Errorf("Execution plan verification failed!")
//return nil, errors.New("Execution plan verification failed!")
//}

////Now you can do the actual FU-related stuff

////Final step: collectively sign the execution plan
//payload, err := protobuf.Encode(req.ExecData.ExecPlan)
//if err != nil {
//log.Errorf("protobuf encode failed: %v", err)
//return nil, err
//}
//h := sha256.New()
//h.Write(payload)

//cosiResp, err := s.cosiService.SignatureRequest(&blscosi.SignatureRequest{
//Message: h.Sum(nil),
//Roster:  s.roster,
//})
//if err != nil {
//log.Errorf("blscosi failed: %v", err)
//return nil, err
//}
//return &UpdateStateReply{Sig: cosiResp.(*blscosi.SignatureResponse).Signature}, nil
////return nil, nil
//}

func (s *Service) CreateState(req *CreateStateRequest) (*CreateStateReply, error) {
	//TODO: Do the same stuff as above in UpdateState
	//Handle the byzcoin part

	return nil, nil
}

//func (s *Service) SpawnDarc(req *SpawnDarcRequest) error {
//return nil
//}

//func (s *Service) CreateSkipchain(req *CreateSkipchainRequest) (*CreateSkipchainReply, error) {
//genesis := skipchain.NewSkipBlock()
//genesis.MaximumHeight = req.MHeight
//genesis.BaseHeight = req.BHeight
//genesis.Roster = req.Roster
//genesis.VerifierIDs = skipchain.VerificationStandard
//reply, err := s.scService.StoreSkipBlock(&skipchain.StoreSkipBlock{
//NewBlock: genesis,
//})
//if err != nil {
//return nil, err
//}
////s.roster = req.Roster
//s.genesis = reply.Latest.Hash
//s.roster = req.Roster
//log.Info("In CreateSkipchain genesis is", reply.Latest.Hash)
//return &CreateSkipchainReply{Genesis: reply.Latest.Hash}, nil
//}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	/// Creating the skipchain here
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
	//db := s.scService.GetDB()
	//latest, err := db.GetLatest(db.GetByID(s.genesis))
	//if err != nil {
	//log.Errorf("Couldn't find the latest block: %v", err)
	//return nil, err
	//}
	//block := latest.Copy()
	//block.Data = enc
	//block.GenesisID = block.SkipChainID()
	//block.Index++
	//_, err = s.scService.StoreSkipBlock(&skipchain.StoreSkipBlock{
	//NewBlock:          block,
	//TargetSkipChainID: latest.SkipChainID(),
	//})
	//if err != nil {
	//log.Errorf("Couldn't store new skipblock: %v", err)
	//return nil, err
	//}

	/////// Now setup byzcoin //////
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
	//s.gMsg = gMsg
	return &InitUnitReply{Genesis: genesisReply.Latest.Hash}, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		cosiService:      c.Service(blscosi.ServiceName).(*blscosi.Service),
		byzService:       c.Service(byzcoin.ServiceName).(*byzcoin.Service),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
	}
	//if err := s.RegisterHandlers(s.CreateState, s.CreateSkipchain, s.InitUnit); err != nil {
	if err := s.RegisterHandlers(s.CreateState, s.InitUnit); err != nil {
		return nil, errors.New("Could not register messages")
	}
	err := byzcoin.RegisterContract(c, ContractKeyValueID, contractValueFromBytes)
	if err != nil {
		return nil, err
	}
	return s, nil
}
