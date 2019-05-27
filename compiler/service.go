package compiler

import (
	"bytes"
	"errors"
	"fmt"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	//bbolt "go.etcd.io/bbolt"
	"math"
	"sync"
)

var pairingSuite = suites.MustFind("bn256.Adapter").(*pairing.SuiteBn256)

var compilerID onet.ServiceID
var storageKey = []byte("storage")

const ServiceName = "CompilerService"
const execPlanSubFtCosi = "execplan_sub_ftcosi"
const execPlanFtCosi = "execplan_ftcosi"

type storage struct {
	sync.Mutex
	Roster *onet.Roster
}

type Service struct {
	// We need to embed the ServiceProcessor, so that incoming messages
	// are correctly handled.
	*onet.ServiceProcessor
	storage *storage
	scServ  *skipchain.Service
	//roster  *onet.Roster

	//ctx        context.Context
	//dbUnit     *bbolt.DB
	//dbTxn      *bbolt.DB
	//bucketUnit []byte
	//bucketTxn  []byte
}

func init() {
	var err error
	compilerID, err = onet.RegisterNewServiceWithSuite(ServiceName, pairingSuite, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&storage{}, &CreateUnitsRequest{},
		&CreateUnitsReply{}, &ExecPlanRequest{}, &ExecPlanReply{},
		&CreateSkipchainRequest{}, &CreateSkipchainReply{}, &LogSkipchainRequest{}, &LogSkipchainReply{})
}

//type us struct {
//K []string
//V []uv
//Data map[string]uv
//}

type ScData struct {
	Data map[string]*Uv
}

type Uv struct {
	R  *onet.Roster
	Pk []kyber.Point
	Nn int
	Nf int
	// Set of transaction IDs
	//Txn ID -> Txn name
	Txns map[string]string
}

func (s *Service) CreateSkipchain(req *CreateSkipchainRequest) (*CreateSkipchainReply, error) {
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
	s.storage.Lock()
	s.storage.Roster = req.Roster
	s.storage.Unlock()
	s.save()
	//s.Genesis = reply.Latest.Hash
	//return &CreateSkipchainReply{Sb: reply.Latest}, nil
	return &CreateSkipchainReply{Genesis: reply.Latest.Hash}, nil
}

func (s *Service) CreateUnits(req *CreateUnitsRequest) (*CreateUnitsReply, error) {
	var data []*UnitData
	scData := make(map[string]*Uv)

	for _, unit := range req.Units {
		uid, err := generateUnitId(unit)
		txnIds := generateTxnIds(unit.Txns)
		if err != nil {
			return nil, err
		}
		val := &Uv{
			R:  unit.Roster,
			Pk: unit.PublicKeys,
			Nn: unit.NumNodes,
			Nf: unit.NumFaulty,
		}
		val.Txns = txnIds
		scData[uid] = val
		data = append(data, &UnitData{UnitId: uid, UnitName: unit.UnitName, Txns: txnIds})
	}
	enc, err := protobuf.Encode(&ScData{
		Data: scData,
	})
	if err != nil {
		log.Errorf("protobufEncode error: %v", err)
		return nil, err
	}
	db := s.scServ.GetDB()
	latest, err := db.GetLatest(db.GetByID(req.Genesis))
	if err != nil {
		return nil, errors.New("Couldn't find the latest block: " + err.Error())
	}
	block := latest.Copy()
	block.Data = enc
	block.GenesisID = block.SkipChainID()
	block.Index++
	//storeSkipBlockReply, err := s.scServ.StoreSkipBlock(&skipchain.StoreSkipBlock{
	_, err = s.scServ.StoreSkipBlock(&skipchain.StoreSkipBlock{
		NewBlock:          block,
		TargetSkipChainID: latest.SkipChainID(),
	})
	if err != nil {
		return nil, err
	}
	return &CreateUnitsReply{Data: data}, nil
	//return &CreateUnitsReply{Data: data, SbID: storeSkipBlockReply.Latest.Hash}, nil
}

func (s *Service) GenerateExecPlan(req *ExecPlanRequest) (*ExecPlanReply, error) {
	s.storage.Lock()
	roster := s.storage.Roster
	s.storage.Unlock()

	n := len(roster.List)
	tree := roster.GenerateNaryTreeWithRoot(n, s.ServerIdentity())
	pi, err := s.CreateProtocol(execPlanFtCosi, tree)
	if err != nil {
		log.Error("CreateProtocol failed:", err)
		return nil, err
	}
	payload, err := protobuf.Encode(req)
	if err != nil {
		log.Error("Protobuf encode failed:", err)
		return nil, err
	}
	cosiProto := pi.(*protocol.BlsCosi)
	cosiProto.Msg = req.Hash()
	cosiProto.Data = payload
	cosiProto.CreateProtocol = s.CreateProtocol
	cosiProto.Threshold = n - n/3
	err = cosiProto.SetNbrSubTree(int(math.Pow(float64(n), 1.0/3.0)))
	if err != nil {
		log.Error("SetNbrSubTree failed:", err)
		return nil, err
	}

	if err := cosiProto.Start(); err != nil {
		log.Error("Starting the cosi protocol failed:", err)
		return nil, err
	}

	reply := &ExecPlanReply{}
	reply.Signature = <-cosiProto.FinalSignature
	return reply, nil
}

func (s *Service) LogSkipchain(req *LogSkipchainRequest) (*LogSkipchainReply, error) {
	db := s.scServ.GetDB()
	latest, err := db.GetLatest(db.GetByID(req.Genesis))
	if err != nil {
		return nil, errors.New("Error latest block:" + err.Error())
	}
	scData := &ScData{}
	err = protobuf.DecodeWithConstructors(latest.Data, scData, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		return nil, err
	}
	for k, v := range scData.Data {
		log.LLvlf1("Functional unit key: %s", k)
		for _, txn := range v.Txns {
			log.LLvlf1("Transaction ID: %s", txn)
		}
		log.Info("==========")
	}
	return &LogSkipchainReply{}, nil
}

func (s *Service) verifyExecPlan(msg []byte, data []byte) bool {
	var req ExecPlanRequest
	if err := protobuf.Decode(data, &req); err != nil {
		log.Error(s.ServerIdentity(), err)
		return false
	}
	if !bytes.Equal(msg, req.Hash()) {
		log.Error(s.ServerIdentity(), "digest doesn't verify")
		return false
	}
	// Check that the units and transactions in the workflow are valid

	db := s.scServ.GetDB()
	latest, err := db.GetLatest(db.GetByID(req.Genesis))
	if err != nil {
		log.Errorf("VerifyExecPlan error: %v", err)
		return false
	}
	scData := &ScData{}
	err = protobuf.DecodeWithConstructors(latest.Data, scData, network.DefaultConstructors(cothority.Suite))
	if err != nil {
		log.Errorf("VerifyExecPlan error: %v", err)
		return false
	}

	for _, wfn := range req.Workflow {
		// val is uv
		if val, ok := scData.Data[wfn.UId]; ok {
			if _, ok := val.Txns[wfn.TId]; ok {
				log.LLvlf1("All good for %s - %s", wfn.UId, wfn.TId)
			} else {
				log.Errorf("%s is not a valid transaction", wfn.TId)
				return false
			}
		} else {
			log.Errorf("%s is not a valid functional unit", wfn.UId)
			return false
		}
	}

	// TODO: Check more stuff
	//err := s.checkUnitKeys(req.UnitIDs...)
	//err := checkUnitKeys(&s.dbUnit, s.bucketUnit, req.UnitIDs...)
	return true
}

func (s *Service) save() error {
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageKey, s.storage)
	if err != nil {
		log.Error("Couldn't save data:", err)
		return err
	}
	return nil
}

func (s *Service) tryLoad() error {
	s.storage = &storage{}
	msg, err := s.Load(storageKey)
	if err != nil {
		log.Error("Load failed:", err)
		return err
	}
	if msg == nil {
		return nil
	}
	var ok bool
	s.storage, ok = msg.(*storage)
	if !ok {
		return errors.New("Data of wrong type")
	}
	return nil
}

func newService(c *onet.Context) (onet.Service, error) {
	//dbUnit, bucketUnit := c.GetAdditionalBucket([]byte("compiler-unit"))
	//dbTxn, bucketTxn := c.GetAdditionalBucket([]byte("compiler-txn"))
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		scServ:           c.Service(skipchain.ServiceName).(*skipchain.Service),
		storage:          &storage{},
		//genesis:          make([]byte, 32),
		//ctx:              context.Background(),
		//dbUnit:     dbUnit,
		//dbTxn:      dbTxn,
		//bucketUnit: bucketUnit,
		//bucketTxn:  bucketTxn,
	}
	if err := s.RegisterHandlers(s.CreateUnits, s.GenerateExecPlan, s.CreateSkipchain, s.LogSkipchain); err != nil {
		return nil, errors.New("couldn't register messages")
	}

	id1, err := s.ProtocolRegister(execPlanSubFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewSubBlsCosi(n, s.verifyExecPlan, pairingSuite)
	})
	if err != nil {
		log.Error(err)
		return nil, err
	}
	id2, err := s.ProtocolRegister(execPlanFtCosi, func(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
		return protocol.NewBlsCosi(n, s.verifyExecPlan, execPlanSubFtCosi, pairingSuite)
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

//func (s *Service) RegisterUnit(req *RegisterUnitRequest) (*RegisterUnitReply, error) {
//keyStr, err := generateUnitKey(req)
//if err != nil {
//log.Errorf("generateUnitKey error: %v", err)
//return nil, err
//}
//key := sha256.Sum256([]byte(keyStr))
//val, err := protobuf.Encode(&us{
//R:  req.Roster,
//Pk: req.PublicKeys,
//Nn: req.NumNodes,
//Nf: req.NumFaulty,
//})
//if err != nil {
//log.Errorf("protobufEncode error: %v", err)
//return nil, err
//}
//err = s.dbUnit.Update(func(tx *bbolt.Tx) error {
//b := tx.Bucket(s.bucketUnit)
//if b == nil {
//return errors.New("nil bucket")
//}
//if ret := b.Get(key[:]); ret != nil {
//return fmt.Errorf("Unit already exists for type:name:numparticipants %d:%v:%d", req.UnitType, req.UnitName, req.NumNodes)
//}
//return b.Put(key[:], val)
//})
//if err != nil {
//log.Errorf("boltdb update error: %v", err)
//return nil, err
//}
//log.LLvl3("Registered unit:", key[:])
//log.LLvl3("Registered unit(string):", string(key[:]))
//return &RegisterUnitReply{Key: hex.EncodeToString(key[:])}, nil
//}

//func (s *Service) RegisterTransaction(req *RegisterTxnRequest) (*RegisterTxnReply, error) {
////err := s.checkUnitKeys(req.UnitID)
////err := checkUnitKeys(s.dbUnit, s.bucketUnit, req.UnitID)
//keyStr, err := generateTxnKey(req)
//if err != nil {
//log.Errorf("generateTxnKey error: %v", err)
//return nil, err
//}
//key := sha256.Sum256([]byte(keyStr))
//val, err := protobuf.Encode(&tv{
//Tt: req.TxnType,
//Tn: req.TxnName,
//})
//if err != nil {
//log.Errorf("protobufEncode error: %v", err)
//return nil, err
//}
//err = s.dbTxn.Update(func(tx *bbolt.Tx) error {
//b := tx.Bucket(s.bucketTxn)
//if b == nil {
//return errors.New("nil bucket")
//}
//if ret := b.Get(key[:]); ret != nil {
//return fmt.Errorf("Txn already exists for type:name %v:%v", req.TxnType, req.TxnName)
//}
//return b.Put(key[:], val)
//})
//if err != nil {
//log.Errorf("boltdb update error: %v", err)
//return nil, err
//}
//return &RegisterTxnReply{Key: hex.EncodeToString(key[:])}, nil
//}
