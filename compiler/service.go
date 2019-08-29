package compiler

import (
	"bytes"
	"crypto/sha256"
	"math"

	"github.com/dedis/protean/sys"
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

var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)
var compilerID onet.ServiceID

const ServiceName = "CompilerService"
const execPlanSubFtCosi = "execplan_sub_ftcosi"
const execPlanFtCosi = "execplan_ftcosi"

type Service struct {
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
		&ExecutionPlanReply{}, &StoreGenesisRequest{}, &StoreGenesisReply{})
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

func (s *Service) StoreGenesis(req *StoreGenesisRequest) (*StoreGenesisReply, error) {
	s.genesis = req.Genesis
	return &StoreGenesisReply{}, nil
}

func (s *Service) CreateUnits(req *CreateUnitsRequest) (*CreateUnitsReply, error) {
	sbd := make(map[string]*uv)
	for _, unit := range req.Units {
		uid := generateUnitID(unit)
		txnMap := generateTxnMap(unit.Txns)
		val := &uv{
			N:    unit.Name,
			R:    unit.Roster,
			Ps:   unit.Publics,
			Txns: txnMap,
		}
		sbd[uid] = val
	}
	enc, err := protobuf.Encode(&sbData{Data: sbd})
	if err != nil {
		log.Errorf("Protobuf encode error: %v", err)
		return nil, err
	}
	err = utils.StoreBlock(s.scService, s.genesis, enc)
	if err != nil {
		log.Errorf("Cannot add block to skipchain: %v", err)
		return nil, err
	}
	return &CreateUnitsReply{}, nil
}

func (s *Service) GenerateExecutionPlan(req *ExecutionPlanRequest) (*ExecutionPlanReply, error) {
	//TODO: THE LEADER SHOULD PREPARE THE EXECUTION PLAN (WITH THE CRYPTO
	//KEYS) AND SEND IT TO THE OTHER NODES. OTHERS VERIFY THAT IT'S
	//CONSISTENT AND SENDS A SIGNATURE
	db := s.scService.GetDB()
	sbData, err := getBlockData(db, s.genesis)
	if err != nil {
		log.Errorf("Cannot get block data: %v", err)
		return nil, err
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
	//var req protean.ExecutionPlan
	var req sys.ExecutionPlan
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
	//sbData, err := getBlockData(db, req.Genesis)
	sbData, err := getBlockData(db, s.genesis)
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

func (s *Service) GetDirectoryInfo(req *DirectoryInfoRequest) (*DirectoryInfoReply, error) {
	db := s.scService.GetDB()
	sbData, err := getBlockData(db, s.genesis)
	if err != nil {
		log.Errorf("Cannot get block data: %v", err)
		return nil, err
	}
	//idx := 0
	//dirInfo := make([]*sys.UnitInfo, len(sbData.Data))
	dir := make(map[string]*sys.UnitInfo)
	for uid, uv := range sbData.Data {
		txnMap := make(map[string]string)
		for txnID, txnName := range uv.Txns {
			txnMap[txnName] = txnID
		}
		//dirInfo[idx] = &sys.UnitInfo{UnitID: uid, UnitName: uv.N, Txns: txnMap}
		dir[uv.N] = &sys.UnitInfo{UnitID: uid, Txns: txnMap}
		//idx++
	}
	//return &DirectoryInfoReply{Data: dirInfo}, nil
	return &DirectoryInfoReply{Directory: dir}, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
	}
	err := s.RegisterHandlers(s.InitUnit, s.StoreGenesis, s.CreateUnits, s.GenerateExecutionPlan, s.GetDirectoryInfo)
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
