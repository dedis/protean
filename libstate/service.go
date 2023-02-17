package libstate

import (
	"bytes"
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"golang.org/x/xerrors"
)

var stateID onet.ServiceID

const ServiceName = "StateService"

var suite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

func init() {
	var err error
	stateID, err = onet.RegisterNewServiceWithSuite(ServiceName, suite, newService)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&InitContractReply{}, &GetContractState{}, &GetContractStateReply{})
	if err != nil {
		panic(err)
	}
	err = byzcoin.RegisterGlobalContract(contracts.ContractKeyValueID, contracts.ContractKeyValueFromBytes)
}

type Service struct {
	*onet.ServiceProcessor
	suite  pairing.SuiteBn256
	bc     *byzcoin.Client
	byzID  skipchain.SkipBlockID
	roster *onet.Roster
}

func (s *Service) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	s.byzID = req.ByzID
	s.roster = req.Roster
	return &InitUnitReply{}, nil
}

func (s *Service) GetContractState(req *GetContractState) (*GetContractStateReply, error) {
	if s.bc == nil {
		s.bc = byzcoin.NewClient(s.byzID, *s.roster)
	}
	pr, err := s.bc.GetProof(req.CID.Slice())
	if err != nil {
		return nil, xerrors.Errorf("failed to get proof from byzcoin: %v", err)
	}
	//TODO: Check this
	proof := core.StateProof{Proof: pr.Proof, Genesis: *s.bc.Genesis}
	return &GetContractStateReply{Proof: proof}, nil
}

func (s *Service) verifyUpdate(cid []byte, root []byte) bool {
	err := func() error {
		if s.bc == nil {
			s.bc = byzcoin.NewClient(s.byzID, *s.roster)
		}
		pr, err := s.bc.GetProof(cid)
		if err != nil {
			return xerrors.Errorf("failed to get proof from byzcoin: %v", err)
		}
		if !bytes.Equal(pr.Proof.InclusionProof.GetRoot(), root) {
			return xerrors.Errorf("merkle roots do not match")
		}
		return nil
	}()
	if err != nil {
		log.Lvlf2("cannot verify update state: %v", err)
		return false
	}
	return true
}

//func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
//	switch tn.ProtocolName() {
//	}
//	return nil, nil
//}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            *suite,
	}
	if err := s.RegisterHandlers(s.InitUnit, s.GetContractState); err != nil {
		return nil, xerrors.New("couldn't register messages")
	}
	return s, nil
}
