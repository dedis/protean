package pristore

import (
	"fmt"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"github.com/dedis/protean/verify"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/calypso"
	"go.dedis.ch/cothority/v3/darc"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

var ServiceName = "PriStoreService"
var priStoreID onet.ServiceID

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
	priStoreID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&AuthorizeRequest{}, &AuthorizeReply{}, &CreateLTSRequest{},
		&CreateLTSReply{}, &SpawnDarcRequest{}, &SpawnDarcReply{},
		&AddWriteRequest{}, &AddWriteReply{}, &AddReadRequest{},
		&AddReadReply{}, &AddReadBatchReply{}, &GetProofRequest{},
		&GetProofReply{}, &GetProofBatchRequest{},
		&GetProofBatchReply{}, &DecryptRequest{}, &DecryptReply{},
		&DecryptBatchRequest{}, &DecryptBatchReply{})
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
	s.gMsg, err = byzcoin.DefaultGenesisMsg(byzcoin.CurrentVersion, s.roster, []string{"spawn:" + calypso.ContractLongTermSecretID}, s.signer.Identity())
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
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(LTS, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
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
	//reply := &CreateLTSReply{}
	ltsReply, err := s.calyService.CreateLTS(&calypso.CreateLTS{
		Proof: gpResp.Proof,
	})
	if err != nil {
		log.Errorf("CreateLTS error: %v", err)
		return nil, err
	}
	s.signerCtr++
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return &CreateLTSReply{Reply: ltsReply, Sig: sig}, nil
}

func (s *Service) SpawnDarc(req *SpawnDarcRequest) (*SpawnDarcReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(DARC, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
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
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return &SpawnDarcReply{Sig: sig}, nil
}

func (s *Service) AddWrite(req *AddWriteRequest) (*AddWriteReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(WRITE, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Add write
	_, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Cannot add write -- Byzcoin add transaction error: %v", err)
		return nil, err
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	reply := &AddWriteReply{
		InstanceID: req.Ctx.Instructions[0].DeriveID(""),
		Sig:        sig,
	}
	return reply, nil
}

func (s *Service) AddRead(req *AddReadRequest) (*AddReadReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(READ, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Add read
	_, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Cannot add read -- Byzcoin add transaction error: %v", err)
		return nil, err
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	reply := &AddReadReply{
		InstanceID: req.Ctx.Instructions[0].DeriveID(""),
		Sig:        sig,
	}
	return reply, nil
}

func (s *Service) AddReadBatch(req *AddReadRequest) (*AddReadBatchReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(READBATCH, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Add read
	_, err = s.byzService.AddTransaction(&byzcoin.AddTxRequest{
		Version:       byzcoin.CurrentVersion,
		SkipchainID:   s.byzID,
		Transaction:   req.Ctx,
		InclusionWait: req.Wait,
	})
	if err != nil {
		log.Errorf("Cannot add read -- Byzcoin add transaction error: %v", err)
		return nil, err
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	reply := &AddReadBatchReply{
		InstanceIDs: make([]byzcoin.InstanceID, len(req.Ctx.Instructions)),
		Sig:         sig,
	}
	for i, inst := range req.Ctx.Instructions {
		reply.InstanceIDs[i] = inst.DeriveID("")
	}
	return reply, nil
}

func (s *Service) GetProof(req *GetProofRequest) (*GetProofReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(PROOF, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Get proof
	gpr, err := s.byzService.GetProof(&byzcoin.GetProof{
		Version: byzcoin.CurrentVersion,
		ID:      s.byzID,
		Key:     req.InstanceID.Slice(),
	})
	if err != nil {
		log.Errorf("GetProof request failed: %v", err)
		return nil, err
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return &GetProofReply{ProofResp: gpr, Sig: sig}, nil
}

func (s *Service) GetProofBatch(req *GetProofBatchRequest) (*GetProofBatchReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(PROOFBATCH, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Get proofs
	proofs := make([]*byzcoin.GetProofResponse, len(req.InstanceIDs))
	for i, id := range req.InstanceIDs {
		gpr, err := s.byzService.GetProof(&byzcoin.GetProof{
			Version: byzcoin.CurrentVersion,
			ID:      s.byzID,
			Key:     id.Slice(),
		})
		if err != nil {
			log.Errorf("GetProof request failed: %v", err)
			return nil, err
		}
		proofs[i] = gpr
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return &GetProofBatchReply{ProofResps: proofs, Sig: sig}, nil
}

func (s *Service) Decrypt(req *DecryptRequest) (*DecryptReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(DEC, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Perform decrypt
	dkr, err := s.calyService.DecryptKey(req.Request)
	if err != nil {
		log.Errorf("Decrypt error: %v", err)
		return nil, err
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return &DecryptReply{Reply: dkr, Sig: sig}, nil
}

func (s *Service) DecryptBatch(req *DecryptBatchRequest) (*DecryptBatchReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(DECBATCH, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Perform decrypt
	replies := make([]*calypso.DecryptKeyReply, len(req.Requests))
	for i, dkr := range req.Requests {
		reply, err := s.calyService.DecryptKey(dkr)
		if err != nil {
			log.Errorf("Decrypt error: %v", err)
			return nil, err
		}
		replies[i] = reply
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return &DecryptBatchReply{Replies: replies, Sig: sig}, nil
}

func (s *Service) verifyExecutionRequest(txnName string, blk *skipchain.SkipBlock, execData *sys.ExecutionData) bool {
	tree := s.roster.GenerateNaryTreeWithRoot(len(s.roster.List), s.ServerIdentity())
	pi, err := s.CreateProtocol(verify.Name, tree)
	if err != nil {
		log.Errorf("Cannot create protocol: %v", err)
		return false
	}
	verifyProto := pi.(*verify.VP)
	verifyProto.Index = execData.Index
	verifyProto.TxnName = txnName
	verifyProto.Block = blk
	verifyProto.ExecPlan = execData.ExecPlan
	verifyProto.ClientSigs = execData.ClientSigs
	verifyProto.CompilerSig = execData.CompilerSig
	verifyProto.UnitSigs = execData.UnitSigs
	err = verifyProto.Start()
	if err != nil {
		log.Errorf("Cannot start protocol: %v", err)
		return false
	}
	if !<-verifyProto.Verified {
		return false
	} else {
		return true
	}
}

func (s *Service) signExecutionPlan(ep *sys.ExecutionPlan) (protocol.BlsSignature, error) {
	epHash, err := utils.ComputeEPHash(ep)
	if err != nil {
		log.Errorf("Cannot compute the execution plan hash: %v", err)
		return nil, err
	}
	cosiResp, err := utils.BlsCosiSign(s.cosiService, s.roster, epHash)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	return cosiResp.(*blscosi.SignatureResponse).Signature, nil
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
