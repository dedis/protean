package tdh

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dedis/protean/sys"
	"github.com/dedis/protean/utils"
	"github.com/dedis/protean/verify"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
)

var storageKey = []byte("storage")
var ServiceName = "TDHService"
var tdhID onet.ServiceID

const propagationTimeout = 20 * time.Second

type storage struct {
	Shared map[DKGID]*dkgprotocol.SharedSecret
	Polys  map[DKGID]*pubPoly
	DKS    map[DKGID]*dkg.DistKeyShare
	sync.Mutex
}

func NewDKGID(in []byte) DKGID {
	var id DKGID
	copy(id[:], in)
	return id
}

type Service struct {
	*onet.ServiceProcessor
	storage     *storage
	scService   *skipchain.Service
	cosiService *blscosi.Service

	roster  *onet.Roster
	genesis skipchain.SkipBlockID
}

func init() {
	var err error
	tdhID, err = onet.RegisterNewService(ServiceName, newService)
	log.ErrFatal(err)
	network.RegisterMessages(&storage{}, &InitUnitRequest{}, &InitUnitReply{},
		&InitDKGRequest{}, &InitDKGReply{}, &DecryptRequest{},
		&DecryptReply{})
}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	// Creating the skipchain here
	cfg := req.Cfg
	log.Infof("Starting InitUnit")
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
	return &InitUnitReply{Genesis: s.genesis}, nil
}

func (s *Service) InitDKG(req *InitDKGRequest) (*InitDKGReply, error) {
	// First verify the execution request
	db := s.scService.GetDB()
	blk, err := db.GetLatest(db.GetByID(s.genesis))
	if err != nil {
		log.Errorf("Cannot get the latest block: %v", err)
		return nil, err
	}
	verified := s.verifyExecutionRequest(DKG, blk, req.ExecData)
	if !verified {
		log.Errorf("Cannot verify execution plan")
		return nil, fmt.Errorf("Cannot verify execution plan")
	}
	// Run DKG
	reply := &InitDKGReply{}
	tree := s.roster.GenerateNaryTreeWithRoot(len(s.roster.List), s.ServerIdentity())
	if tree == nil {
		log.Error("Cannot create tree with roster", s.roster.List)
		return nil, errors.New("Error while generating tree")
	}
	pi, err := s.CreateProtocol(dkgprotocol.Name, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	setupDKG := pi.(*dkgprotocol.Setup)
	err = setupDKG.SetConfig(&onet.GenericConfig{Data: req.ID[:]})
	if err != nil {
		log.Errorf("Could not set config: %v", err)
		return nil, err
	}
	setupDKG.Wait = true
	setupDKG.KeyPair = s.getKeyPair()
	err = pi.Start()
	if err != nil {
		log.Errorf("Start protocol error: %v", err)
		return nil, err
	}
	log.Lvl3("Started DKG-protocol - waiting for done", len(s.roster.List))
	select {
	case <-setupDKG.Finished:
		shared, dks, err := setupDKG.SharedSecret()
		if err != nil {
			log.Errorf("SharedSecret call error: %v", err)
			return nil, err
		}
		reply = &InitDKGReply{
			X: shared.X,
		}
		s.storage.Lock()
		s.storage.Shared[req.ID] = shared
		s.storage.Polys[req.ID] = &pubPoly{s.Suite().Point().Base(), dks.Commits}
		s.storage.DKS[req.ID] = dks
		s.storage.Unlock()
		err = s.save()
		if err != nil {
			return nil, err
		}
	case <-time.After(propagationTimeout):
		return nil, errors.New("DKG did not finish in time")
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	reply.Sig = sig
	return reply, nil
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

	// Decrypt
	reply := &DecryptReply{}
	reply.C = req.Ct.C
	s.storage.Lock()
	shared, ok := s.storage.Shared[req.ID]
	if !ok {
		s.storage.Unlock()
		log.Errorf("Cannot find ID: %v", req.ID)
		return reply, errors.New("No DKG entry found for the given ID")
	}
	shared = shared.Clone()
	pp, ok := s.storage.Polys[req.ID]
	if !ok {
		s.storage.Unlock()
		log.Errorf("Cannot find ID: %v", req.ID)
		return nil, errors.New("No DKG entry found for the given ID")
	}
	reply.X = shared.X.Clone()
	commits := make([]kyber.Point, len(pp.Commits))
	for i, c := range pp.Commits {
		commits[i] = c.Clone()
	}
	bb := pp.B.Clone()
	s.storage.Unlock()

	numNodes := len(s.roster.List)
	threshold := numNodes - (numNodes-1)/3
	tree := s.roster.GenerateNaryTreeWithRoot(numNodes, s.ServerIdentity())
	pi, err := s.CreateProtocol(TDHProtoName, tree)
	if err != nil {
		return nil, errors.New("failed to create decrypt protocol: " + err.Error())
	}
	decProto := pi.(*TDHDecrypt)
	decProto.Ct = req.Ct
	decProto.Xc = req.Xc
	decProto.Gen = req.Gen
	decProto.Shared = shared
	decProto.Poly = share.NewPubPoly(s.Suite(), bb, commits)
	err = decProto.SetConfig(&onet.GenericConfig{Data: req.ID[:]})
	if err != nil {
		log.Errorf("Could not set config: %v", err)
		return nil, err
	}

	log.Lvl3("Starting decryption protocol")
	err = decProto.Start()
	if err != nil {
		return nil, errors.New("Failed to start the decryption protocol: " + err.Error())
	}
	if !<-decProto.Decrypted {
		return nil, errors.New("Decryption got refused")
	}
	log.Lvl3("Decryption protocol is done.")
	reply.XhatEnc, err = share.RecoverCommit(cothority.Suite, decProto.Uis, threshold, numNodes)
	if err != nil {
		return nil, errors.New("Failed to recover commit: " + err.Error())
	}
	// Collectively sign the execution plan
	sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	if err != nil {
		log.Errorf("Cannot produce blscosi signature: %v", err)
		return nil, err
	}
	reply.Sig = sig
	return reply, nil
}

//func (s *Service) Decrypt(req *DecryptRequest) (*DecryptReply, error) {
//reply := &DecryptReply{}
//nodes := len(s.roster.List)
//threshold := nodes - (nodes-1)/3
//tree := s.roster.GenerateNaryTreeWithRoot(nodes, s.ServerIdentity())
//pi, err := s.CreateProtocol(TDHProtoName, tree)
//if err != nil {
//return nil, errors.New("failed to create decrypt protocol: " + err.Error())
//}
//decProto := pi.(*TDHDecrypt)
////decProto.U = req.U
//decProto.Ct = req.Ct
//decProto.Xc = req.Xc
//decProto.Gen = req.Gen
//encoded, err := hexToBytes(req.ID)
//if err != nil {
//log.Errorf("Could not convert string to byte array: %v", err)
//return nil, err
//}
//err = decProto.SetConfig(&onet.GenericConfig{Data: encoded})
//if err != nil {
//log.Errorf("Could not set config: %v", err)
//return nil, err
//}

//s.storage.Lock()
//decProto.Shared = s.storage.Shared[req.ID]
//pp := s.storage.Polys[req.ID]
//reply.X = s.storage.Shared[req.ID].X.Clone()
//commits := make([]kyber.Point, len(pp.Commits))
//for i, c := range pp.Commits {
//commits[i] = c.Clone()
//}
//decProto.Poly = share.NewPubPoly(s.Suite(), pp.B.Clone(), commits)
//s.storage.Unlock()

//log.Lvl3("Starting decryption protocol")
//err = decProto.Start()
//if err != nil {
//return nil, errors.New("Failed to start the decryption protocol: " + err.Error())
//}
//if !<-decProto.Decrypted {
//return nil, errors.New("Decryption got refused")
//}
//log.Lvl3("Decryption protocol is done.")
//reply.XhatEnc, err = share.RecoverCommit(cothority.Suite, decProto.Uis, threshold, nodes)
//if err != nil {
//return nil, errors.New("Failed to recover commit: " + err.Error())
//}
////reply.C = req.C
//reply.C = req.Ct.C
//log.Lvl3("Decryption success")
//return reply, nil
//}

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
	//verifyProto.ClientSigs = execData.ClientSigs
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

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3(s.ServerIdentity(), tn.ProtocolName(), conf)
	switch tn.ProtocolName() {
	case dkgprotocol.Name:
		pi, err := dkgprotocol.NewSetup(tn)
		if err != nil {
			return nil, err
		}
		setupDKG := pi.(*dkgprotocol.Setup)
		setupDKG.KeyPair = s.getKeyPair()
		go func(idSlice []byte) {
			<-setupDKG.Finished
			shared, dks, err := setupDKG.SharedSecret()
			if err != nil {
				log.Error(err)
				return
			}
			id := NewDKGID(idSlice)
			log.Lvlf3("%v got shared %v", s.ServerIdentity(), shared)
			s.storage.Lock()
			s.storage.Shared[id] = shared
			s.storage.DKS[id] = dks
			s.storage.Unlock()
			err = s.save()
			if err != nil {
				log.Error(err)
			}
		}(conf.Data)
		return pi, nil
	case TDHProtoName:
		id := NewDKGID(conf.Data)
		s.storage.Lock()
		shared, ok := s.storage.Shared[id]
		shared = shared.Clone()
		s.storage.Unlock()
		if !ok {
			return nil, fmt.Errorf("Could not find shared data with id: %v", id)
		}
		pi, err := NewTDHDecrypt(tn)
		if err != nil {
			return nil, err
		}
		dec := pi.(*TDHDecrypt)
		dec.Shared = shared
		return dec, nil
	}
	return nil, nil
}

func (s *Service) getKeyPair() *key.Pair {
	return &key.Pair{
		Public:  s.ServerIdentity().ServicePublic(ServiceName),
		Private: s.ServerIdentity().ServicePrivate(ServiceName),
	}
}

func hexToBytes(str string) ([]byte, error) {
	return hex.DecodeString(str)
}

func (s *Service) save() error {
	s.storage.Lock()
	defer s.storage.Unlock()
	err := s.Save(storageKey, s.storage)
	if err != nil {
		log.Errorf("Could not save data: %v", err)
		return err
	}
	return nil
}

func (s *Service) tryLoad() error {
	s.storage = &storage{}
	defer func() {
		if len(s.storage.Shared) == 0 {
			//s.storage.Shared = make(map[string]*dkgprotocol.SharedSecret)
			s.storage.Shared = make(map[DKGID]*dkgprotocol.SharedSecret)
		}
		if len(s.storage.Polys) == 0 {
			//s.storage.Polys = make(map[string]*pubPoly)
			s.storage.Polys = make(map[DKGID]*pubPoly)
		}
		if len(s.storage.DKS) == 0 {
			//s.storage.DKS = make(map[string]*dkg.DistKeyShare)
			s.storage.DKS = make(map[DKGID]*dkg.DistKeyShare)
		}
	}()
	msg, err := s.Load(storageKey)
	if err != nil {
		log.Errorf("Load storage failed: %v", err)
		return err
	}
	if msg == nil {
		return nil
	}
	var ok bool
	s.storage, ok = msg.(*storage)
	if !ok {
		return fmt.Errorf("Data of wrong type")
	}
	return nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		scService:        c.Service(skipchain.ServiceName).(*skipchain.Service),
		cosiService:      c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	err := s.RegisterHandlers(s.InitUnit, s.InitDKG, s.Decrypt)
	if err != nil {
		log.Errorf("Cannot register handlers: %v", err)
		return nil, err
	}
	err = s.tryLoad()
	if err != nil {
		return nil, err
	}
	return s, nil
}
