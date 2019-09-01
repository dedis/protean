package compiler

import (
	"bytes"
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
	genesisReply, err := utils.CreateGenesisBlock(s.scService, req.ScCfg, req.Roster)
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
		log.Infof("Unit: %s - UID: %s", val.N, uid)
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

	numNodes := len(s.roster.List)
	tree := s.roster.GenerateNaryTreeWithRoot(numNodes, s.ServerIdentity())
	pi, err := s.CreateProtocol(execPlanFtCosi, tree)
	if err != nil {
		log.Errorf("CreateProtocol failed: %v", err)
		return nil, err
	}
	msgBuf, err := utils.ComputeEPHash(execPlan)
	if err != nil {
		log.Errorf("Error computing the hash of the execution plan: %v", err)
		return nil, err
	}
	dataBuf, err := protobuf.Encode(&epData{Ep: execPlan, Sm: req.SigMap})
	if err != nil {
		return nil, err
	}
	cosiProto := pi.(*protocol.BlsCosi)
	cosiProto.Msg = msgBuf
	cosiProto.Data = dataBuf
	cosiProto.CreateProtocol = s.CreateProtocol
	cosiProto.Threshold = numNodes - (numNodes-1)/3
	err = cosiProto.SetNbrSubTree(int(math.Pow(float64(numNodes), 1.0/3.0)))
	if err != nil {
		log.Errorf("SetNbrSubTree failed: %v", err)
		return nil, err
	}

	err = cosiProto.Start()
	if err != nil {
		log.Errorf("Starting the cosi protocol failed: %v", err)
		return nil, err
	}
	reply := &ExecutionPlanReply{}
	reply.ExecPlan = execPlan
	reply.Signature = <-cosiProto.FinalSignature
	return reply, nil
}

func (s *Service) verifyExecutionPlan(msg []byte, data []byte) bool {
	var epd epData
	err := protobuf.Decode(data, &epd)
	if err != nil {
		log.Errorf("%s protobuf decode error: %v:", s.ServerIdentity(), err)
		return false
	}
	execPlan := epd.Ep
	digest, err := utils.ComputeEPHash(execPlan)
	if err != nil {
		log.Errorf("%s cannot compute the hash of the execution plan: %v:", s.ServerIdentity(), err)
		return false
	}
	if !bytes.Equal(msg, digest) {
		log.Errorf("%s digest does not verify", s.ServerIdentity())
		return false
	}
	db := s.scService.GetDB()
	sbData, err := getBlockData(db, s.genesis)
	if err != nil {
		log.Errorf("Cannot get block data: %v", err)
		return false
	}
	for _, wfn := range execPlan.Workflow.Nodes {
		// val is uv
		if val, ok := sbData.Data[wfn.UID]; ok {
			if _, ok := val.Txns[wfn.TID]; !ok {
				log.Errorf("%s is not a valid transaction", wfn.TID)
				return false
			}
		} else {
			log.Errorf("%s is not a valid functional unit", wfn.UID)
			return false
		}
	}
	err = verifyDag(execPlan.Workflow.Nodes)
	if err != nil {
		log.Errorf("Verify execution plan error: %v", err)
		return false
	}
	err = verifyAuthentication(execPlan.Workflow, epd.Sm)
	if err != nil {
		log.Errorf("Verify execution plan error: %v", err)
		return false
	}
	return true
}

func (s *Service) GetDirectoryInfo(req *DirectoryInfoRequest) (*DirectoryInfoReply, error) {
	db := s.scService.GetDB()
	sbData, err := getBlockData(db, s.genesis)
	if err != nil {
		log.Errorf("Cannot get block data: %v", err)
		return nil, err
	}
	dir := make(map[string]*sys.UnitInfo)
	for uid, uv := range sbData.Data {
		txnMap := make(map[string]string)
		for txnID, txnName := range uv.Txns {
			txnMap[txnName] = txnID
		}
		dir[uv.N] = &sys.UnitInfo{UnitID: uid, Txns: txnMap}
	}
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
