package core

import (
	"github.com/dedis/protean/core/protocol"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
	"golang.org/x/xerrors"
)

var coreID onet.ServiceID

const ServiceName = "CoreService"

var suite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

func init() {
	var err error
	coreID, err = onet.RegisterNewServiceWithSuite(ServiceName, suite, newService)
	network.RegisterMessages(&TestSignRequest{}, &TestSignReply{})
	if err != nil {
		panic(err)
	}
}

type Service struct {
	*onet.ServiceProcessor
	suite          pairing.SuiteBn256
	blscosiService *blscosi.Service
}

func (s *Service) TestSign(req *TestSignRequest) (*TestSignReply, error) {
	nodeCount := len(req.Roster.List)
	threshold := nodeCount - (nodeCount-1)/3
	tree := req.Roster.GenerateNaryTreeWithRoot(nodeCount, s.ServerIdentity())
	pi, err := s.CreateProtocol(protocol.NameTestBlsCosi, tree)
	if err != nil {
		return nil, xerrors.Errorf("failed to create protocol: %v", err)
	}
	blsProto := pi.(*protocol.TestBlsCosi)
	blsProto.Msg = req.Msg
	blsProto.Threshold = threshold
	err = blsProto.Start()
	if err != nil {
		return nil, xerrors.Errorf("failed to start the protocol: %v", err)
	}
	if !<-blsProto.Executed {
		return nil, xerrors.New("signing got refused")
	}
	sig := blsProto.FinalSignature
	h := s.suite.Hash()
	h.Write(req.Msg)
	return &TestSignReply{
		Hash:      h.Sum(nil),
		Signature: sig,
	}, nil
}

//func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
//	log.Lvlf1("I'm in %s", tn.ServerIdentity())
//	switch tn.ProtocolName() {
//	case protocol.NameTestBlsCosi:
//		pi, err := protocol.NewBlsCosi(tn)
//		if err != nil {
//			return nil, xerrors.Errorf("creating protocol instance: %v", err)
//		}
//		proto := pi.(*protocol.TestBlsCosi)
//		return proto, nil
//	}
//	return nil, nil
//}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		suite:            *suite,
		blscosiService:   c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	if err := s.RegisterHandlers(s.TestSign); err != nil {
		return nil, xerrors.New("couldn't register messages")
	}
	return s, nil
}
