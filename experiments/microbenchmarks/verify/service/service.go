package service

import (
	"github.com/dedis/protean/experiments/microbenchmarks/verify/protocol"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

var verifierID onet.ServiceID

const ServiceName = "VerifyService"

func init() {
	var err error
	verifierID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
}

type Verifier struct {
	*onet.ServiceProcessor
	blsService *blscosi.Service
}

func (s *Verifier) Verify(req *VerifyRequest) (*VerifyReply, error) {
	nodeCount := len(req.Roster.List)
	threshold := nodeCount - (nodeCount-1)/3
	tree := req.Roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(protocol.VerifyProtoName, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return &VerifyReply{Success: false}, err
	}
	verifyPi := pi.(*protocol.Verify)
	verifyPi.Threshold = threshold
	verifyPi.InputData = req.InputData
	verifyPi.StateProofs = req.StateProofs
	verifyPi.ExecReq = req.ExecReq
	verifyPi.KP = protean.GetBLSKeyPair(s.ServerIdentity())
	err = verifyPi.Start()
	if err != nil {
		return &VerifyReply{Success: false}, xerrors.Errorf("Failed to start the protocol: " + err.Error())
	}
	if !<-verifyPi.Verified {
		return &VerifyReply{Success: false}, xerrors.New("verify protocol failed")
	}
	return &VerifyReply{Success: true}, nil
}

func (s *Verifier) NewProtocol(tn *onet.TreeNodeInstance,
	conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3(s.ServerIdentity(), tn.ProtocolName(), conf)
	switch tn.ProtocolName() {
	case protocol.VerifyProtoName:
		pi, err := protocol.NewVerify(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*protocol.Verify)
		proto.KP = protean.GetBLSKeyPair(s.ServerIdentity())
		return proto, nil
	default:
		return nil, nil
	}
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Verifier{
		ServiceProcessor: onet.NewServiceProcessor(c),
		blsService:       c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	err := s.RegisterHandlers(s.Verify)
	if err != nil {
		log.Errorf("Registering handlers failed: %v", err)
		return nil, err
	}
	return s, nil
}
