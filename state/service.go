package state

import (
	//"crypto/sha256"

	"crypto/sha256"
	"fmt"

	"github.com/ceyhunalp/protean_code"
	"github.com/ceyhunalp/protean_code/utils"
	"github.com/ceyhunalp/protean_code/verify"
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
	roster    *onet.Roster
	genesis   skipchain.SkipBlockID
	byzID     skipchain.SkipBlockID
	gMsg      *byzcoin.CreateGenesisBlock
	signer    darc.Signer
	signerCtr uint64

	byzService  *byzcoin.Service
	cosiService *blscosi.Service
	scService   *skipchain.Service
}

func init() {
	var err error
	stateID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&CreateStateRequest{}, &CreateStateReply{}, &UpdateStateRequest{},
		&UpdateStateReply{}, &SpawnDarcRequest{}, &SpawnDarcReply{},
		&GetProofRequest{}, &GetProofReply{})
}

//TODO: Update state probably needs to return something more than an error.
//Maybe something about the state update? (e.g. proof?)
func (s *Service) UpdateState(req *UpdateStateRequest) (*UpdateStateReply, error) {
	// Before we send Byzcoin transactions to update state, we need to make
	// sure that the execution plan has the necesssary signatures
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Couldn't get the latest block: %v", err)
		return nil, err
	}
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
	//err = verifyProto.Start()
	//if !<-verifyProto.Verified {
	//log.Errorf("Execution plan verification failed!")
	//return nil, fmt.Errorf("Execution plan verification failed!")
	//} else {
	//log.Lvl2("Execution plan verification success!")
	//}
	verified := s.verifyExecutionPlan(blk, req.ExecData)
	if !verified {
		log.Errorf("[UpdateState] Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}

	//Now you can do the actual FU-related stuff
	reply := &UpdateStateReply{}
	reply.AddTxResp, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("[UpdateState]: Add transaction failed: %v", err)
		return nil, err
	}

	//Final step: collectively sign the execution plan
	payload, err := protobuf.Encode(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("protobuf encode failed: %v", err)
		return nil, err
	}
	h := sha256.New()
	h.Write(payload)

	cosiResp, err := s.cosiService.SignatureRequest(&blscosi.SignatureRequest{
		Message: h.Sum(nil),
		Roster:  s.roster,
	})
	if err != nil {
		log.Errorf("blscosi failed: %v", err)
		return nil, err
	}
	return &UpdateStateReply{Sig: cosiResp.(*blscosi.SignatureResponse).Signature}, nil
}

func (s *Service) CreateState(req *CreateStateRequest) (*CreateStateReply, error) {
	var err error
	reply := &CreateStateReply{}
	reply.AddTxResp, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("[CreateState] Add transaction failed: %v", err)
		return nil, err
	}
	reply.InstID = req.Ctx.Instructions[0].DeriveID("")
	return reply, nil
}

func (s *Service) SpawnDarc(req *SpawnDarcRequest) (*SpawnDarcReply, error) {
	darcBuf, err := req.Darc.ToProto()
	if err != nil {
		log.Errorf("[SpawnDarc] Could not convert darc to protobuf: %v", err)
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
		log.Errorf("[SpawnDarc] Signing the transaction failed: %v", err)
		return nil, err
	}
	_, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("[SpawnDarc] Add transaction failed: %v", err)
		return nil, err
	}
	s.signerCtr++
	return &SpawnDarcReply{}, nil
}

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
		log.Errorf("[GetProof] GetProof request failed: %v", err)
		return nil, err
	}
	return reply, nil
}

func (s *Service) verifyExecutionPlan(blk *skipchain.SkipBlock, execData *protean.ExecutionData) bool {
	tree := s.roster.GenerateNaryTreeWithRoot(len(s.roster.List), s.ServerIdentity())
	pi, err := s.CreateProtocol(verify.Name, tree)
	if err != nil {
		log.Errorf("[verifyExecutionPlan] Cannot create protocol: %v", err)
		return false
	}
	verifyProto := pi.(*verify.VP)
	verifyProto.Block = blk
	verifyProto.Index = execData.Index
	verifyProto.ExecPlan = execData.ExecPlan
	verifyProto.PlanSig = execData.PlanSig
	verifyProto.SigMap = execData.SigMap
	//verifyProto.FaultThreshold = req.FaultThreshold
	err = verifyProto.Start()
	if err != nil {
		log.Errorf("[verifyExecutionPlan] Cannot start protocol: %v", err)
		return false
	}
	if !<-verifyProto.Verified {
		return false
	} else {
		return true
	}
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		cosiService:      c.Service(blscosi.ServiceName).(*blscosi.Service),
		byzService:       c.Service(byzcoin.ServiceName).(*byzcoin.Service),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
	}
	err := s.RegisterHandlers(s.InitUnit, s.CreateState, s.UpdateState, s.SpawnDarc, s.GetProof)
	if err != nil {
		log.Errorf("[newService] Could not register messages")
		return nil, err
	}
	err = byzcoin.RegisterContract(c, ContractKeyValueID, contractValueFromBytes)
	if err != nil {
		log.Errorf("[newService] Could not register contract %s: %v", ContractKeyValueID, err)
		return nil, err
	}
	return s, nil
}
