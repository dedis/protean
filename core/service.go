package core

import (
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
)

var coreID onet.ServiceID

const ServiceName = "CoreService"

var suite = suites.MustFind("bn256.adapter").(*pairing.SuiteBn256)

func init() {
	var err error
	coreID, err = onet.RegisterNewServiceWithSuite(ServiceName, suite, newService)
	//network.RegisterMessages(&TestSignRequest{}, &TestSignReply{})
	if err != nil {
		panic(err)
	}
}

type Service struct {
	*onet.ServiceProcessor
	//suite          pairing.SuiteBn256
	//blscosiService *blscosi.Service
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
		//suite:            *suite,
		//blscosiService:   c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	//if err := s.RegisterHandlers(s.TestSign); err != nil {
	//	return nil, xerrors.New("couldn't register messages")
	//}
	return s, nil
}
