package service

import (
	"github.com/dedis/protean/easyneff/base"
	"github.com/dedis/protean/easyneff/protocol"
	"github.com/dedis/protean/experiments/microbenchmarks/shuffle/protocol/verify"
	protean "github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/blscosi"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"time"
)

var shuffleID onet.ServiceID

const ServiceName = "ShuffleMicroService"
const shuffleTimeout = 150 * time.Second

func init() {
	var err error
	shuffleID, err = onet.RegisterNewService(ServiceName, newService)
	if err != nil {
		panic(err)
	}
}

type ShuffleSvc struct {
	*onet.ServiceProcessor
	blsService *blscosi.Service
}

func (s *ShuffleSvc) Shuffle(req *ShuffleRequest) (*ShuffleReply, error) {
	tree := req.Roster.GenerateNaryTree(1)
	pi, err := s.CreateProtocol(protocol.ShuffleProtoName, tree)
	if err != nil {
		return nil, err
	}
	neff := pi.(*protocol.NeffShuffle)
	neff.ShufInput = &req.Input
	neff.Threshold = req.Threshold
	if err := pi.Start(); err != nil {
		return nil, err
	}
	select {
	case shufProof := <-neff.FinalProof:
		if req.IsBasic {
			// Shuffle done
			return &ShuffleReply{Proofs: shufProof}, nil
		} else {
			// 2nd stage: collectively verify the shuffles
			nodeCount := len(req.Roster.List)
			tree := req.Roster.GenerateNaryTreeWithRoot(nodeCount-1, s.ServerIdentity())
			pi, err := s.CreateProtocol(protocol.VerifyProtoName, tree)
			if err != nil {
				return nil, err
			}
			shufVerify := pi.(*verify.ShuffleVerify)
			shufVerify.ShufInput = &req.Input
			shufVerify.ShufOutput = &shufProof
			shufVerify.KP = protean.GetBLSKeyPair(s.ServerIdentity())
			if err != nil {
				log.Errorf("failed to prepare the input hashes: %v", err)
				return nil, err
			}
			// Verification function
			shufVerify.ShufVerify = s.ShuffleVerify
			shufVerify.Threshold = req.Threshold
			err = shufVerify.Start()
			if err != nil {
				return nil, xerrors.Errorf("Failed to start the verification protocol: " + err.Error())
			}
			if !<-shufVerify.Verified {
				return nil, xerrors.New("shuffle verify failed")
			}
			return &ShuffleReply{Proofs: shufProof, OutputReceipts: shufVerify.OutputReceipts}, nil
		}
	case <-time.After(shuffleTimeout):
		return nil, xerrors.New("timeout waiting for shuffle")
	}
	return nil, nil
}

func (s *ShuffleSvc) ShuffleVerify(sp *base.ShuffleOutput, G, H kyber.Point,
	initialPairs protean.ElGamalPairs, publics []kyber.Point) error {
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

func splitPairs(pairs protean.ElGamalPairs) ([]kyber.Point, []kyber.Point) {
	ps := pairs.Pairs
	xs := make([]kyber.Point, len(ps))
	ys := make([]kyber.Point, len(ps))
	for i := range ps {
		xs[i] = ps[i].K
		ys[i] = ps[i].C
	}
	return xs, ys
}

func (s *ShuffleSvc) NewProtocol(tn *onet.TreeNodeInstance,
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
	case verify.VerifyProtoName:
		pi, err := protocol.NewShuffleVerify(tn)
		if err != nil {
			return nil, err
		}
		proto := pi.(*protocol.ShuffleVerify)
		proto.KP = protean.GetBLSKeyPair(s.ServerIdentity())
		proto.ShufVerify = s.ShuffleVerify
		return proto, nil
	}
	return nil, nil
}

func newService(c *onet.Context) (onet.Service, error) {
	s := &ShuffleSvc{
		ServiceProcessor: onet.NewServiceProcessor(c),
		blsService:       c.Service(blscosi.ServiceName).(*blscosi.Service)}
	err := s.RegisterHandlers(s.Shuffle)
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
