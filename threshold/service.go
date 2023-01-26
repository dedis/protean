package threshold

import (
	"fmt"
	"github.com/dedis/protean/threshold/protocol"
	"go.dedis.ch/cothority/v3/blscosi"
	"golang.org/x/xerrors"
	"sync"
	"time"

	dkgprotocol "go.dedis.ch/cothority/v3/dkg/pedersen"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/pedersen"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

var thresholdID onet.ServiceID
var ServiceName = "ThreshCryptoService"
var storageKey = []byte("storage")

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
	storage    *storage
	roster     *onet.Roster
	blsService *blscosi.Service
}

func init() {
	var err error
	thresholdID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
	network.RegisterMessages(&storage{}, &InitUnitRequest{}, &InitUnitReply{},
		&InitDKGRequest{}, &InitDKGReply{}, &DecryptRequest{},
		&DecryptReply{})
}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	s.roster = req.Roster
	return &InitUnitReply{}, nil
}

func (s *Service) InitDKG(req *InitDKGRequest) (*InitDKGReply, error) {
	// Run DKG
	reply := &InitDKGReply{}
	tree := s.roster.GenerateNaryTreeWithRoot(len(s.roster.List)-1, s.ServerIdentity())
	if tree == nil {
		log.Error("Cannot create tree with roster", s.roster.List)
		return nil, xerrors.New("error while generating tree")
	}
	pi, err := s.CreateProtocol(dkgprotocol.Name, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	setupDKG := pi.(*dkgprotocol.Setup)
	err = setupDKG.SetConfig(&onet.GenericConfig{Data: req.ID[:]})
	if err != nil {
		log.Errorf("could not set config: %v", err)
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
		return nil, xerrors.New("DKG did not finish in time")
	}
	// Collectively sign the execution plan
	//sig, err := s.signExecutionPlan(req.ExecData.ExecPlan)
	//if err != nil {
	//	log.Errorf("Cannot produce blscosi signature: %v", err)
	//	return nil, err
	//}
	//reply.Sig = sig
	return reply, nil
}

func (s *Service) Decrypt(req *DecryptRequest) (*DecryptReply, error) {
	// First verify the execution request
	//db := s.scService.GetDB()
	//blk, err := db.GetLatest(db.GetByID(s.genesis))
	//if err != nil {
	//	log.Errorf("Cannot get the latest block: %v", err)
	//	return nil, err
	//}
	//verified := s.verifyExecutionRequest(DEC, blk, req.ExecData)
	//if !verified {
	//	log.Errorf("Cannot verify execution plan")
	//	return nil, fmt.Errorf("cannot verify execution plan")
	//}
	// create protocol
	nodeCount := len(s.roster.List)
	tree := s.roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(protocol.DecryptProtoName, tree)
	if err != nil {
		return nil, xerrors.New("failed to create decryptShare protocol: " + err.Error())
	}
	decProto := pi.(*protocol.ThreshDecrypt)
	decProto.Cs = req.Cs
	decProto.BlsPublic = s.ServerIdentity().ServicePublic(blscosi.ServiceName)
	decProto.BlsPublics = s.roster.ServicePublics(blscosi.ServiceName)
	decProto.BlsSk = s.ServerIdentity().ServicePrivate(blscosi.ServiceName)
	decProto.Threshold = nodeCount - (nodeCount-1)/3
	err = decProto.SetConfig(&onet.GenericConfig{Data: req.ID[:]})
	if err != nil {
		log.Errorf("Could not set config: %v", err)
		return nil, err
	}
	s.storage.Lock()
	shared, ok := s.storage.Shared[req.ID]
	if !ok {
		s.storage.Unlock()
		log.Errorf("Cannot find ID: %v", req.ID)
		return nil, xerrors.New("no DKG entry found for the given ID")
	}
	decProto.Shared = shared.Clone()
	pp, ok := s.storage.Polys[req.ID]
	if !ok {
		s.storage.Unlock()
		log.Errorf("Cannot find ID: %v", req.ID)
		return nil, xerrors.New("no DKG entry found for the given ID")
	}
	commits := make([]kyber.Point, len(pp.Commits))
	for i, c := range pp.Commits {
		commits[i] = c.Clone()
	}
	decProto.Poly = share.NewPubPoly(s.Suite(), pp.B.Clone(), commits)
	s.storage.Unlock()
	log.Lvl3("Starting decryption protocol")
	err = decProto.Start()
	if err != nil {
		return nil, xerrors.New("Failed to start the decryption protocol: " + err.Error())
	}
	if !<-decProto.Decrypted {
		return nil, xerrors.New("decryption got refused")
	}
	return &DecryptReply{Ps: decProto.Ptexts, Signature: decProto.FinalSignature}, nil
}

func (s *Service) getKeyPair() *key.Pair {
	return &key.Pair{
		Public:  s.ServerIdentity().ServicePublic(ServiceName),
		Private: s.ServerIdentity().ServicePrivate(ServiceName),
	}
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
			s.storage.Shared = make(map[DKGID]*dkgprotocol.SharedSecret)
		}
		if len(s.storage.Polys) == 0 {
			s.storage.Polys = make(map[DKGID]*pubPoly)
		}
		if len(s.storage.DKS) == 0 {
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
		return fmt.Errorf("Store of wrong type")
	}
	return nil
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
	case protocol.DecryptProtoName:
		id := NewDKGID(conf.Data)
		s.storage.Lock()
		shared, ok := s.storage.Shared[id]
		shared = shared.Clone()
		s.storage.Unlock()
		if !ok {
			return nil, xerrors.Errorf("couldn't find shared data with id: %x", id)
		}
		pi, err := protocol.NewThreshDecrypt(tn)
		if err != nil {
			return nil, err
		}
		dec := pi.(*protocol.ThreshDecrypt)
		dec.Shared = shared
		dec.BlsPublic = s.ServerIdentity().ServicePublic(blscosi.ServiceName)
		dec.BlsPublics = s.roster.ServicePublics(blscosi.ServiceName)
		dec.BlsSk = s.ServerIdentity().ServicePrivate(blscosi.ServiceName)
		return dec, nil
	}
	return nil, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		blsService:       c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	err := s.RegisterHandlers(s.InitUnit, s.InitDKG, s.Decrypt)
	if err != nil {
		log.Errorf("couldn't register handlers: %v", err)
		return nil, err
	}
	err = s.tryLoad()
	if err != nil {
		return nil, err
	}
	return s, nil
}
