package service

import (
	"github.com/dedis/protean/experiments/microbenchmarks/sign/protocol/bdn"
	"github.com/dedis/protean/experiments/microbenchmarks/sign/protocol/bls"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

var signerID onet.ServiceID

const ServiceName = "SignerService"

func init() {
	var err error
	signerID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
}

type Signer struct {
	*onet.ServiceProcessor
	blsService *blscosi.Service
}

func (s *Signer) BLSSign(req *BLSSignRequest) (*BLSSignReply, error) {
	nodeCount := len(req.Roster.List)
	threshold := nodeCount - (nodeCount-1)/3
	tree := req.Roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(bls.BLSSignProtoName, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	signPi := pi.(*bls.Sign)
	signPi.Threshold = threshold
	signPi.OutputData = req.OutputData
	signPi.ExecReq = req.ExecReq
	signPi.KP = protean.GetBLSKeyPair(s.ServerIdentity())
	err = signPi.Start()
	if err != nil {
		return nil, xerrors.Errorf("Failed to start the protocol: " + err.Error())
	}
	if !<-signPi.Signed {
		return nil, xerrors.New("sign protocol failed")
	}
	return &BLSSignReply{Receipts: signPi.Receipts}, nil
}

func (s *Signer) BDNSign(req *BDNSignRequest) (*BDNSignReply, error) {
	nodeCount := len(req.Roster.List)
	threshold := nodeCount - (nodeCount-1)/3
	tree := req.Roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
	pi, err := s.CreateProtocol(bdn.BDNSignProtoName, tree)
	if err != nil {
		log.Errorf("Create protocol error: %v", err)
		return nil, err
	}
	signPi := pi.(*bdn.BDNSign)
	signPi.Threshold = threshold
	signPi.OutputData = req.OutputData
	signPi.ExecReq = req.ExecReq
	signPi.KP = protean.GetBLSKeyPair(s.ServerIdentity())
	err = signPi.Start()
	if err != nil {
		return nil, xerrors.Errorf("Failed to start the protocol: " + err.Error())
	}
	if !<-signPi.Signed {
		return nil, xerrors.New("sign protocol failed")
	}
	return &BDNSignReply{Receipts: signPi.Receipts}, nil
}

func (s *Signer) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3(s.ServerIdentity(), tn.ProtocolName(), conf)
	switch tn.ProtocolName() {
	case bls.BLSSignProtoName:
		pi, err := bls.NewSign(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*bls.Sign)
		proto.KP = protean.GetBLSKeyPair(s.ServerIdentity())
		return proto, nil
	case bdn.BDNSignProtoName:
		pi, err := bdn.NewBDNSign(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*bdn.BDNSign)
		proto.KP = protean.GetBLSKeyPair(s.ServerIdentity())
		return proto, nil
	default:
		return nil, nil
	}
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &Signer{
		ServiceProcessor: onet.NewServiceProcessor(c),
		blsService:       c.Service(blscosi.ServiceName).(*blscosi.Service),
	}
	err := s.RegisterHandlers(s.BLSSign, s.BDNSign)
	if err != nil {
		log.Errorf("Registering handlers failed: %v", err)
		return nil, err
	}
	return s, nil
}
