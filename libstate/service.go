package libstate

import (
	"bytes"
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libstate/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

var stateID onet.ServiceID

const ServiceName = "StateService"

var suite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

func init() {
	var err error
	stateID, err = onet.RegisterNewServiceWithSuite(ServiceName,
		suite, newService)
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&InitContract{}, &GetContractState{}, &GetContractStateReply{})
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
	proof := core.StateProof{Proof: pr.Proof}
	return &GetContractStateReply{Proof: proof}, nil
}

func (s *Service) ReadState(req *ReadState) (*ReadStateReply, error) {
	if s.bc == nil {
		s.bc = byzcoin.NewClient(s.byzID, *s.roster)
	}
	pr, err := s.bc.GetProof(req.CID.Slice())
	if err != nil {
		return nil, xerrors.Errorf("failed to get proof from byzcoin: %v", err)
	}
	proof := core.StateProof{Proof: pr.Proof}
	buf, err := protobuf.Encode(&proof)
	if err != nil {
		return nil, xerrors.Errorf("failed to encode proof: %v", err)
	}
	nodeCount := len(s.roster.List)
	threshold := nodeCount - (nodeCount-1)/3
	tree := s.roster.GenerateNaryTreeWithRoot(nodeCount, s.ServerIdentity())
	pi, err := s.CreateProtocol(protocol.RSProtocol, tree)
	if err != nil {
		return nil, xerrors.Errorf("failed to create protocol: %v", err)
	}
	rsProto := pi.(*protocol.ReadState)
	rsProto.CID = req.CID
	rsProto.SP = &proof
	rsProto.ProofBytes = buf
	rsProto.Keys = req.Keys
	rsProto.Threshold = threshold
	err = rsProto.Start()
	if err != nil {
		return nil, xerrors.Errorf("failed to start the protocol: %v", err)
	}
	if !<-rsProto.Executed {
		return nil, xerrors.New("couldn't read state")
	}
	data := rsProto.ReadState
	sig := rsProto.FinalSignature
	return &ReadStateReply{Data: *data, Signature: sig}, nil
}

func (s *Service) verifyGetContractState(cid byzcoin.InstanceID, data []byte) bool {
	err := func() error {
		if s.bc == nil {
			s.bc = byzcoin.NewClient(s.byzID, *s.roster)
		}
		pr, err := s.bc.GetProof(cid.Slice())
		if err != nil {
			return xerrors.Errorf("failed to get proof from byzcoin: %v", err)
		}
		proof := core.StateProof{Proof: pr.Proof}
		buf, err := protobuf.Encode(&proof)
		if err != nil {
			return xerrors.Errorf("failed to encode proof: %v", err)
		}
		if !bytes.Equal(data, buf) {
			return xerrors.New("state mismatch")
		}
		return nil
	}()
	if err != nil {
		log.Lvlf2("cannot verify request: %v", err)
		return false
	}
	return true
}

func (s *Service) verifyReadState(cid byzcoin.InstanceID, proofBytes []byte, sp *core.StateProof) bool {
	err := func() error {
		if s.bc == nil {
			s.bc = byzcoin.NewClient(s.byzID, *s.roster)
		}
		pr, err := s.bc.GetProof(cid.Slice())
		if err != nil {
			return xerrors.Errorf("failed to get proof from byzcoin: %v", err)
		}
		sp.Proof = pr.Proof
		buf, err := protobuf.Encode(sp)
		if err != nil {
			return xerrors.Errorf("failed to encode proof: %v", err)
		}
		if !bytes.Equal(proofBytes, buf) {
			return xerrors.New("state mismatch")
		}
		return nil
	}()
	if err != nil {
		log.Lvlf2("cannot verify request: %v", err)
		return false
	}
	return true
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

func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	switch tn.ProtocolName() {
	case protocol.GCSProtocol:
		pi, err := protocol.NewGetContractState(tn)
		if err != nil {
			return nil, xerrors.Errorf("creating protocol instance: %v", err)
		}
		p := pi.(*protocol.GetContractState)
		p.Verify = s.verifyGetContractState
		return p, nil
	case protocol.RSProtocol:
		pi, err := protocol.NewReadState(tn)
		if err != nil {
			return nil, xerrors.Errorf("creating protocol instance: %v", err)
		}
		p := pi.(*protocol.ReadState)
		p.Verify = s.verifyReadState
		return p, nil
	}
	return nil, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            *suite,
	}
	if err := s.RegisterHandlers(s.InitUnit, s.GetContractState, s.ReadState); err != nil {
		return nil, xerrors.New("couldn't register messages")
	}
	return s, nil
}
