package easyneff

import (
	"github.com/dedis/protean/easyneff/protocol"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"golang.org/x/xerrors"
	"time"

	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

var easyneffID onet.ServiceID

const ServiceName = "EasyneffService"

func init() {
	var err error
	easyneffID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
	network.RegisterMessages(&InitUnitRequest{}, &InitUnitReply{},
		&ShuffleRequest{}, &ShuffleReply{})
}

// EasyNeff is the service that runs a Neff shuffle.
type EasyNeff struct {
	*onet.ServiceProcessor
	roster     *onet.Roster
	blsService *blscosi.Service
}

func (s *EasyNeff) InitUnit(req *InitUnitRequest) (*InitUnitReply, error) {
	s.roster = req.Roster
	return &InitUnitReply{}, nil
}

// Shuffle performs Neff shuffle.
func (s *EasyNeff) Shuffle(req *ShuffleRequest) (*ShuffleReply, error) {
	// create a "line" tree
	tree := s.roster.GenerateNaryTree(1)
	pi, err := s.CreateProtocol(protocol.ShuffleProtoName, tree)
	if err != nil {
		return nil, err
	}
	neff := pi.(*protocol.NeffShuffle)
	neff.Request = protocol.Request{Pairs: req.Pairs, H: req.H}
	if err := pi.Start(); err != nil {
		return nil, err
	}
	select {
	case proof := <-neff.FinalProof:
		nodeCount := len(s.roster.List)
		tree := s.roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
		pi, err := s.CreateProtocol(protocol.VerifyProtoName, tree)
		if err != nil {
			return nil, err
		}
		shufVerify := pi.(*protocol.ShuffleVerify)
		shufVerify.Threshold = nodeCount - (nodeCount-1)/3
		shufVerify.Pairs = req.Pairs
		shufVerify.H = req.H
		shufVerify.SProof = proof
		// Public keys to verify shuffle proofs
		shufVerify.Publics = s.roster.Publics()
		// Cryptographic identites for BLS
		shufVerify.BlsPublic = s.ServerIdentity().ServicePublic(blscosi.ServiceName)
		shufVerify.BlsPublics = s.roster.ServicePublics(blscosi.ServiceName)
		shufVerify.BlsSk = s.ServerIdentity().ServicePrivate(blscosi.ServiceName)
		// Verification function
		shufVerify.Verify = s.ShuffleVerify
		err = shufVerify.Start()
		if err != nil {
			return nil, xerrors.Errorf("Failed to start the verification protocol: " + err.Error())
		}
		if !<-shufVerify.Verified {
			return nil, xerrors.New("shuffle verify failed")
		}
		return &ShuffleReply{Proofs: proof.Proofs, Signature: shufVerify.FinalSignature}, nil
	case <-time.After(time.Second * time.Duration(len(s.roster.List))):
		return nil, xerrors.New("timeout waiting for shuffle")
	}
}

func (s *EasyNeff) ShuffleVerify(sp *protocol.ShuffleProof, G, H kyber.Point,
	initialPairs []utils.ElGamalPair, publics []kyber.Point) error {
	x, y := splitPairs(initialPairs)
	for i, proof := range sp.Proofs {
		// check that the signature on the proof is correct
		if err := schnorr.Verify(cothority.Suite, publics[i], proof.Proof,
			proof.Signature); err != nil {
			return err
		}
		// check that the shuffle is correct
		xbar, ybar := splitPairs(proof.Pairs)
		if err := Verify(proof.Proof, G, H, x, y, xbar, ybar); err != nil {
			return err
		}
		// reset the x and y for the next iteration
		x, y = xbar, ybar
	}
	return nil
}

// Verify  verifies the proof of a Neff shuffle.
func Verify(prf []byte, G, H kyber.Point, x, y, xbar, ybar []kyber.Point) error {
	if len(x) < 2 || len(y) < 2 || len(xbar) < 2 || len(ybar) < 2 {
		return xerrors.New("cannot verify less than 2 points")
	}
	verifier := shuffle.Verifier(cothority.Suite, G, H, x, y, xbar, ybar)
	return proof.HashVerify(cothority.Suite, "", verifier, prf)
}

func splitPairs(pairs []utils.ElGamalPair) ([]kyber.Point, []kyber.Point) {
	xs := make([]kyber.Point, len(pairs))
	ys := make([]kyber.Point, len(pairs))
	for i := range pairs {
		xs[i] = pairs[i].K
		ys[i] = pairs[i].C
	}
	return xs, ys
}

func (s *EasyNeff) NewProtocol(tn *onet.TreeNodeInstance,
	conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	log.Lvl3(s.ServerIdentity(), tn.ProtocolName(), conf)
	switch tn.ProtocolName() {
	case protocol.ShuffleProtoName:
		pi, err := protocol.NewShuffleProtocolDefaultSuite(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*protocol.NeffShuffle)
		return proto, nil
	case protocol.VerifyProtoName:
		pi, err := protocol.NewShuffleVerify(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*protocol.ShuffleVerify)
		proto.Publics = s.roster.Publics()
		proto.BlsPublic = s.ServerIdentity().ServicePublic(blscosi.ServiceName)
		proto.BlsPublics = s.roster.ServicePublics(blscosi.ServiceName)
		proto.BlsSk = s.ServerIdentity().ServicePrivate(blscosi.ServiceName)
		proto.Verify = s.ShuffleVerify
		return proto, nil
	}
	return nil, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &EasyNeff{
		ServiceProcessor: onet.NewServiceProcessor(c),
		blsService:       c.Service(blscosi.ServiceName).(*blscosi.Service)}
	err := s.RegisterHandlers(s.InitUnit, s.Shuffle)
	if err != nil {
		log.Errorf("Could not register handlers: %v", err)
		return nil, err

	}
	_, err = s.ProtocolRegister(protocol.ShuffleProtoName, protocol.NewShuffleProtocolDefaultSuite)
	if err != nil {
		log.Errorf("Could not register protocols: %v", err)
		return nil, err
	}
	return s, nil
}
