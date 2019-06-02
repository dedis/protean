package easyneff

import (
	"errors"
	"time"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
)

const shuffleProtoName = "neffshuffle_protocol"
const serviceName = "easyneff"

var serviceID onet.ServiceID

func init() {
	var err error
	serviceID, err = onet.RegisterNewService(serviceName, newService)
	if err != nil {
		panic(err)
	}
}

// EasyNeff is the service that runs a Neff shuffle.
type EasyNeff struct {
	*onet.ServiceProcessor
}

// Shuffle performs a shuffle request.
func (s *EasyNeff) Shuffle(req *Request) (*Response, error) {
	// create a "line" tree
	tree := req.Roster.GenerateNaryTree(1)
	pi, err := s.CreateProtocol(shuffleProtoName, tree)
	if err != nil {
		return nil, err
	}
	shufflePi := pi.(*ShuffleProtocol)
	shufflePi.InitialReq = *req
	if err := pi.Start(); err != nil {
		return nil, err
	}
	select {
	case proof := <-shufflePi.FinalProof:
		return &proof, nil
	case <-time.After(time.Second * time.Duration(len(req.Roster.List))):
		return nil, errors.New("timeout waiting for shuffle proof")
	}
}

// Verify a convenience function to verify all the proofs. G and H are public
// generators. The initial ElGamal pairs must be given by initialPairs.
func (r *Response) Verify(G, H kyber.Point, initialPairs []ElGamalPair, publics []kyber.Point) error {
	x, y := splitPairs(initialPairs)
	for i, proof := range r.Proofs {
		// check that the signature on the proof is correct
		if err := schnorr.Verify(cothority.Suite, publics[i], proof.Proof, proof.Signature); err != nil {
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

func newService(c *onet.Context) (onet.Service, error) {
	s := &EasyNeff{
		ServiceProcessor: onet.NewServiceProcessor(c),
	}
	if err := s.RegisterHandlers(s.Shuffle); err != nil {
		return nil, err
	}
	if _, err := s.ProtocolRegister(shuffleProtoName, NewShuffleProtocolDefaultSuite); err != nil {
		return nil, err
	}
	return s, nil
}
