package compiler

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/ceyhunalp/protean_code"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"math"
)

var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)

var compilerID onet.ServiceID
var storageKey = []byte("storage")

const ServiceName = "CompilerService"
const execPlanSubFtCosi = "execplan_sub_ftcosi"
const execPlanFtCosi = "execplan_ftcosi"

//type storage struct {
//sync.Mutex
//Roster *onet.Roster
//}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	scServ *skipchain.Service
	roster *onet.Roster
	//storage *storage
	//ctx        context.Context
}

func init() {
	var err error
	compilerID, err = onet.RegisterNewServiceWithSuite(ServiceName, pairingSuite, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&CreateUnitsRequest{},
		&CreateUnitsReply{}, &ExecutionPlanRequest{}, &ExecutionPlanReply{},
		&protean.CreateSkipchainRequest{}, &protean.CreateSkipchainReply{}, &LogSkipchainRequest{}, &LogSkipchainReply{})
}

func (s *Service) CreateSkipchain(req *protean.CreateSkipchainRequest) (*protean.CreateSkipchainReply, error) {
	genesis := skipchain.NewSkipBlock()
	genesis.MaximumHeight = req.MHeight
	genesis.BaseHeight = req.BHeight
	genesis.Roster = req.Roster
	genesis.VerifierIDs = skipchain.VerificationStandard
	reply, err := s.scServ.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock: genesis,
	})
	if err != nil {
		return nil, err
	}
	log.Info("CreateSkipchain success:", reply.Latest.Hash)
	s.roster = req.Roster
	//s.genesis = reply.Latest.Hash
	log.Info("In CreateSkipchain genesis is", reply.Latest.Hash)
	return &protean.CreateSkipchainReply{Genesis: reply.Latest.Hash}, nil
}

func (s *Service) CreateUnits(req *CreateUnitsRequest) (*CreateUnitsReply, error) {
	var data []*UnitData
	sd := make(map[string]*uv)

	for _, unit := range req.Units {
		uid, err := generateUnitID(unit)
		txnIDs := generateTxnIDs(unit.Txns)
		if err != nil {
			return nil, err
		}
		val := &uv{
			R:  unit.Roster,
			Ps: unit.Publics,
			Nn: unit.NumNodes,
			Nf: unit.NumFaulty,
		}
		val.Txns = txnIDs
		sd[uid] = val
		data = append(data, &UnitData{UnitID: uid, UnitName: unit.UnitName, Txns: txnIDs})
	}
	enc, err := protobuf.Encode(&sbData{
		Data: sd,
	})
	if err != nil {
		log.Errorf("protobufEncode error: %v", err)
		return nil, err
	}
	log.Info("In CreateUnits genesis is", req.Genesis)
	db := s.scServ.GetDB()
	latest, err := db.GetLatest(db.GetByID(req.Genesis))
	if err != nil {
		return nil, errors.New("Couldn't find the latest block: " + err.Error())
	}
	block := latest.Copy()
	block.Data = enc
	block.GenesisID = block.SkipChainID()
	block.Index++
	_, err = s.scServ.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock:          block,
		TargetSkipChainID: latest.SkipChainID(),
	})
	if err != nil {
		return nil, err
	}
	return &CreateUnitsReply{Data: data}, nil
}

func (s *Service) GenerateExecutionPlan(req *ExecutionPlanRequest) (*ExecutionPlanReply, error) {
	log.Info("In GenerateExecutionPlan genesis is", req.Genesis)

	//TODO: THE LEADER SHOULD PREPARE THE EXECUTION PLAN (WITH THE CRYPTO
	//KEYS) AND SEND IT TO THE OTHER NODES. OTHERS VERIFY THAT IT'S
	//CONSISTENT AND SENDS A SIGNATURE

	db := s.scServ.GetDB()
	sbData, err := getBlockData(db, req.Genesis)
	if err != nil {
		return nil, err
	}

	for k, v := range sbData.Data {
		log.Lvlf1("SBDATA: %s %d", k, v.Nn)
	}

	execPlan, err := prepareExecutionPlan(sbData, req)
	if err != nil {
		return nil, err
	}

	n := len(s.roster.List)
	tree := s.roster.GenerateNaryTreeWithRoot(n, s.ServerIdentity())
	pi, err := s.CreateProtocol(execPlanFtCosi, tree)
	if err != nil {
		log.Error("CreateProtocol failed:", err)
		return nil, err
	}
	payload, err := protobuf.Encode(execPlan)
	if err != nil {
		log.Error("Protobuf encode failed:", err)
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
		log.Error("SetNbrSubTree failed:", err)
		return nil, err
	}

	log.Info("Before proto start:", s.ServerIdentity())
	if err := cosiProto.Start(); err != nil {
		log.Error("Starting the cosi protocol failed:", err)
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
	log.Info("In verifyExecutionPlan:", s.ServiceID())
	log.Info("Starting verifyexecplan in", s.ServerIdentity())
	var req ExecutionPlan
	if err := protobuf.Decode(data, &req); err != nil {
		log.Error(s.ServerIdentity(), err)
		return false
	}
	h := sha256.New()
	h.Write(data)
	digest := h.Sum(nil)
	if !bytes.Equal(msg, digest) {
		log.Error(s.ServerIdentity(), "digest doesn't verify")
		return false
	}
	// Check that the units and transactions in the workflow are valid
	db := s.scServ.GetDB()
	sbData, err := getBlockData(db, req.Genesis)
	if err != nil {
		return false
	}
	for _, wfn := range req.Workflow {
		// val is uv
		if val, ok := sbData.Data[wfn.UID]; ok {
			if _, ok := val.Txns[wfn.TID]; ok {
				log.LLvlf1("All good for %s - %s", wfn.UID, wfn.TID)
			} else {
				log.Errorf("%s is not a valid transaction", wfn.TID)
				return false
			}
		} else {
			log.Errorf("%s is not a valid functional unit", wfn.UID)
			return false
		}
	}

	valid := verifyDag(req.Workflow)

	// TODO: Check more stuff
	return valid
}

func (s *Service) LogSkipchain(req *LogSkipchainRequest) (*LogSkipchainReply, error) {
	log.Info("In LogSkipchain genesis is", req.Genesis)
	db := s.scServ.GetDB()
	sbData, err := getBlockData(db, req.Genesis)
	if err != nil {
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
//return errors.New("Data of wrong type")
//}
//return nil
//}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		scServ:           c.Service(skipchain.ServiceName).(*skipchain.Service),
		//storage:          &storage{},
		//ctx:              context.Background(),
	}
	if err := s.RegisterHandlers(s.CreateUnits, s.GenerateExecutionPlan, s.CreateSkipchain, s.LogSkipchain); err != nil {
		return nil, errors.New("couldn't register messages")
	}

	id1, err := s.ProtocolRegister(execPlanSubFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewSubBlsCosi(n, s.verifyExecutionPlan, pairingSuite)
	})
	if err != nil {
		log.Error(err)
		return nil, err
	}
	id2, err := s.ProtocolRegister(execPlanFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewBlsCosi(n, s.verifyExecutionPlan, execPlanSubFtCosi, pairingSuite)
	})
	if err != nil {
		log.Error(err)
		return nil, err
	}

	fmt.Println("IDs are:", id1, id2)
	//if err := s.tryLoad(); err != nil {
	//log.Error(err)
	//return nil, err
	//}
	return s, nil
}
