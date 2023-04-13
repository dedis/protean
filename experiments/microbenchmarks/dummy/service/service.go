package service

import (
	"github.com/dedis/protean/experiments/microbenchmarks/dummy/protocol"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

var dummyID onet.ServiceID

const ServiceName = "DummySvcService"

func init() {
	var err error
	dummyID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
}

type DummySvc struct {
	*onet.ServiceProcessor
	blsService *blscosi.Service
}

func (s *DummySvc) Dummy(req *DummyRequest) (*DummyReply, error) {
	nodeCount := len(req.Roster.List)
	//threshold := nodeCount - (nodeCount-1)/3
	threshold := 1
	tree := req.Roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(protocol.DummyProtoName, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	dummyPi := pi.(*protocol.Dummy)
	dummyPi.Threshold = threshold
	dummyPi.OutputData = req.OutputData
	err = dummyPi.Start()
	if err != nil {
		return nil, xerrors.Errorf("Failed to start the protocol: " + err.Error())
	}
	if !<-dummyPi.Finished {
		return nil, xerrors.New("dummy protocol failed")
	}
	return &DummyReply{}, nil
}

func (s *DummySvc) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3(s.ServerIdentity(), tn.ProtocolName(), conf)
	switch tn.ProtocolName() {
	case protocol.DummyProtoName:
		pi, err := protocol.NewDummy(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*protocol.Dummy)
		return proto, nil
	default:
		return nil, nil
	}
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &DummySvc{
		ServiceProcessor: onet.NewServiceProcessor(c),
		blsService:       c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	err := s.RegisterHandlers(s.Dummy)
	if err != nil {
		log.Errorf("Registering handlers failed: %v", err)
		return nil, err
	}
	return s, nil
}
