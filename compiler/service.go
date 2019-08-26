package compiler

import (
	"bytes"
	"crypto/sha256"
	"math"

	"github.com/dedis/protean"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

//var storageKey = []byte("storage")

var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)
var compilerID onet.ServiceID

const ServiceName = "CompilerService"
const execPlanSubFtCosi = "execplan_sub_ftcosi"
const execPlanFtCosi = "execplan_ftcosi"

type Service struct {
	//ctx        context.Context
	*onet.ServiceProcessor
	roster  *onet.Roster
	genesis skipchain.SkipBlockID

	scService *skipchain.Service
}

func init() {
	var err error
	compilerID, err = onet.RegisterNewServiceWithSuite(ServiceName, pairingSuite, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&CreateUnitsRequest{}, &CreateUnitsReply{}, &ExecutionPlanRequest{},
		&ExecutionPlanReply{}, &LogSkipchainRequest{}, &LogSkipchainReply{})
}

func (s *Service) CreateUnits(req *CreateUnitsRequest) (*CreateUnitsReply, error) {
	//var dirInfo []*protean.UnitInfo
	dirInfo := make([]*protean.UnitInfo, len(req.Units))
	sbd := make(map[string]*uv)
	for i, unit := range req.Units {
		uid, err := generateUnitID(unit)
		if err != nil {
			log.Errorf("Error in generating unit IDs: %v", err)
			return nil, err
		}
		txnIDs := generateTxnIDs(unit.Txns)
		val := &uv{
			R:  unit.Roster,
			Ps: unit.Publics,
			Nn: unit.NumNodes,
			Nf: unit.NumFaulty,
		}
		val.Txns = txnIDs
		sbd[uid] = val
		//dirInfo = append(dirInfo, &protean.UnitInfo{UnitID: uid, UnitName: unit.UnitName, Txns: txnIDs})
		dirInfo[i] = &protean.UnitInfo{UnitID: uid, UnitName: unit.UnitName, Txns: txnIDs}
	}
	enc, err := protobuf.Encode(&sbData{
		Data: sbd,
	})
	if err != nil {
		log.Errorf("Protobuf encode error: %v", err)
		return nil, err
	}
	err = utils.StoreBlock(s.scService, req.Genesis, enc)
	if err != nil {
		log.Errorf("Cannot add block to skipchain: %v", err)
		return nil, err
	}
	return &CreateUnitsReply{UnitDirectory: dirInfo}, nil
}

func (s *Service) GenerateExecutionPlan(req *ExecutionPlanRequest) (*ExecutionPlanReply, error) {
	log.Info("In GenerateExecutionPlan genesis is", req.Genesis)

	//TODO: THE LEADER SHOULD PREPARE THE EXECUTION PLAN (WITH THE CRYPTO
	//KEYS) AND SEND IT TO THE OTHER NODES. OTHERS VERIFY THAT IT'S
	//CONSISTENT AND SENDS A SIGNATURE
	db := s.scService.GetDB()
	sbData, err := getBlockData(db, req.Genesis)
	if err != nil {
		log.Errorf("Cannot get block data: %v", err)
		return nil, err
	}

	for k, v := range sbData.Data {
		log.Lvlf1("SBDATA: %s %d", k, v.Nn)
	}

	execPlan, err := prepareExecutionPlan(sbData, req)
	if err != nil {
		log.Errorf("Preparing the execution plan failed: %v", err)
		return nil, err
	}

	n := len(s.roster.List)
	tree := s.roster.GenerateNaryTreeWithRoot(n, s.ServerIdentity())
	pi, err := s.CreateProtocol(execPlanFtCosi, tree)
	if err != nil {
		log.Errorf("CreateProtocol failed: %v", err)
		return nil, err
	}
	payload, err := protobuf.Encode(execPlan)
	if err != nil {
		log.Errorf("Protobuf encode failed: %v", err)
		return nil, err
	}
	h := sha256.New()
	h.Write(payload)

	cosiProto := pi.(*protocol.BlsCosi)
	cosiProto.Msg = h.Sum(nil)
	cosiProto.Data = payload
	cosiProto.CreateProtocol = s.CreateProtocol
	cosiProto.Threshold = n - n/3
	err = cosiProto.SetNbrSubTree(int(math.Pow(float64(n), 1.0/3.0)))
	if err != nil {
		log.Errorf("SetNbrSubTree failed: %v", err)
		return nil, err
	}

	log.Info("Before proto start:", s.ServerIdentity())
	if err := cosiProto.Start(); err != nil {
		log.Errorf("Starting the cosi protocol failed: %v", err)
		return nil, err
	}
	log.Info("After proto start:", s.ServerIdentity())
	reply := &ExecutionPlanReply{}
	reply.ExecPlan = execPlan
	reply.Signature = <-cosiProto.FinalSignature
	log.Info("Signature ready:", reply.Signature)
	return reply, nil
}

func (s *Service) verifyExecutionPlan(msg []byte, data []byte) bool {
	valid := false
	var req protean.ExecutionPlan
	if err := protobuf.Decode(data, &req); err != nil {
		log.Errorf("%s Protobuf decode error: %v:", s.ServerIdentity(), err)
		return valid
	}
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)
	if !bytes.Equal(msg, digest) {
		log.Errorf("%s: digest does not verify", s.ServerIdentity())
		return valid
	}
	// Check that the units and transactions in the workflow are valid
	db := s.scService.GetDB()
	sbData, err := getBlockData(db, req.Genesis)
	if err != nil {
		log.Errorf("Cannot get block data: %v", err)
		return valid
	}
	for _, wfn := range req.Workflow {
		// val is uv
		if val, ok := sbData.Data[wfn.UID]; ok {
			if _, ok := val.Txns[wfn.TID]; ok {
				log.LLvlf1("All good for %s - %s", wfn.UID, wfn.TID)
			} else {
				log.Errorf("%s is not a valid transaction", wfn.TID)
				return valid
			}
		} else {
			log.Errorf("%s is not a valid functional unit", wfn.UID)
			return valid
		}
	}
	valid = verifyDag(req.Workflow)
	// TODO: Check more stuff
	return valid
}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	genesisReply, err := utils.CreateGenesisBlock(s.scService, req.ScData, req.Roster)
	if err != nil {
		log.Errorf("Cannot create skipchain genesis block: %v", err)
		return nil, err
	}
	s.genesis = genesisReply.Latest.Hash
	s.roster = req.Roster
	return &InitUnitReply{Genesis: s.genesis}, nil
}

func (s *Service) LogSkipchain(req *LogSkipchainRequest) (*LogSkipchainReply, error) {
	log.Info("In LogSkipchain genesis is", req.Genesis)
	db := s.scService.GetDB()
	sbData, err := getBlockData(db, req.Genesis)
	if err != nil {
		log.Errorf("Cannot get block data: %v", err)
		return nil, err
	}
	for k, v := range sbData.Data {
		log.LLvlf1("Functional unit key: %s", k)
		for _, txn := range v.Txns {
			log.LLvlf1("Transaction ID: %s", txn)
		}
		log.Info("==========")
	}
	return &LogSkipchainReply{}, nil
}

//func (s *Service) save() error {
//s.storage.Lock()
//defer s.storage.Unlock()
//err := s.Save(storageKey, s.storage)
//if err != nil {
//log.Error("Couldn't save data:", err)
//return err
//}
//return nil
//}

//func (s *Service) tryLoad() error {
//s.storage = &storage{}
//msg, err := s.Load(storageKey)
//if err != nil {
//log.Error("Load failed:", err)
//return err
//}
//if msg == nil {
//return nil
//}
//var ok bool
//s.storage, ok = msg.(*storage)
//if !ok {
//return fmt.Errorf("Data of wrong type")
//}
//return nil
//}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
		//storage:          &storage{},
		//ctx:              context.Background(),
	}
	err := s.RegisterHandlers(s.InitUnit, s.CreateUnits, s.GenerateExecutionPlan, s.LogSkipchain)
	if err != nil {
		log.Errorf("Cannot register handlers: %v", err)
		return nil, err
	}
	_, err = s.ProtocolRegister(execPlanSubFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewSubBlsCosi(n, s.verifyExecutionPlan, pairingSuite)
	})
	if err != nil {
		log.Errorf("Cannot register protocol %s: %v", execPlanSubFtCosi, err)
		return nil, err
	}
	_, err = s.ProtocolRegister(execPlanFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewBlsCosi(n, s.verifyExecutionPlan, execPlanSubFtCosi, pairingSuite)
	})
	if err != nil {
		log.Errorf("Cannot register protocol %s: %v", execPlanFtCosi, err)
		return nil, err
	}
	return s, nil
}
