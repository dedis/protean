package easyneff

import (
	"errors"
	"time"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// ShuffleProtocol is a protocol for running the Neff shuffle in a chain.
type ShuffleProtocol struct {
	*onet.TreeNodeInstance
	FinalProof chan ShuffleReply
	InitialReq ShuffleRequest

	suite     proof.Suite
	reqChan   chan reqChan
	proofChan chan proofChan
}

type reqChan struct {
	*onet.TreeNode
	ShuffleRequest
}

type proofChan struct {
	*onet.TreeNode
	Proof
}

// NewShuffleProtocol initializes the shuffle protocol, it is used as a
// callback when creating new shuffle protocol instances.
func NewShuffleProtocol(n *onet.TreeNodeInstance, suite proof.Suite) (onet.ProtocolInstance, error) {
	p := &ShuffleProtocol{
		TreeNodeInstance: n,
		FinalProof:       make(chan ShuffleReply, 1),
		suite:            suite,
	}
	if err := p.RegisterChannels(&p.reqChan, &p.proofChan); err != nil {
		return nil, err
	}
	return p, nil
}

// NewShuffleProtocolDefaultSuite initializes the shuffle protocol, it is used
// as a callback when creating new shuffle protocol instances. The suite it
// uses is the default from cothority.
func NewShuffleProtocolDefaultSuite(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	return NewShuffleProtocol(n, cothority.Suite)
}

// Start implements the onet.ProtocolInstance interface.
func (p *ShuffleProtocol) Start() error {
	if !p.IsRoot() {
		return errors.New("protocol must start on root")
	}
	if !treeIsChain(p.Root(), len(p.List())) {
		return errors.New("tree must be a line")
	}
	// start the shuffle
	return p.SendTo(p.Root(), &p.InitialReq)
}

// Dispatch implements the onet.ProtocolInstance interface.
func (p *ShuffleProtocol) Dispatch() error {
	defer p.Done()

	// handle the first request
	req := <-p.reqChan
	X, Y := splitPairs(req.Pairs)
	Xbar, Ybar, prover := shuffle.Shuffle(p.suite, req.G, req.H, X, Y, p.suite.RandomStream())
	prf, err := proof.HashProve(p.suite, "", prover)
	if err != nil {
		return err
	}
	log.LLvl3(p.ServerIdentity(), "got req")

	// sign it and reply to the root and send it to the next node
	sig, err := schnorr.Sign(p.suite, p.Private(), prf)
	if err != nil {
		return err
	}
	signedPrf := Proof{
		Pairs:     combinePairs(Xbar, Ybar),
		Proof:     prf,
		Signature: sig,
	}
	if err := p.SendTo(p.Root(), &signedPrf); err != nil {
		return err
	}
	// Nothing more to do if I'm a child.
	if p.IsLeaf() {
		return nil
	}
	// Send to the next node in the chain.
	newReq := ShuffleRequest{
		Pairs: signedPrf.Pairs,
		G:     req.G,
		H:     req.H,
	}
	log.LLvl3(p.ServerIdentity(), "sent new req")
	if err := p.SendTo(p.Children()[0], &newReq); err != nil {
		return err
	}
	// No need to collect other proof if I'm not the root.
	if !p.IsRoot() {
		return nil
	}
	proofMap := make(map[onet.TreeNodeID]Proof)
	for i := 0; i < len(p.List()); i++ {
		select {
		case prf := <-p.proofChan:
			log.LLvl3(p.ServerIdentity(), "got proof", i)
			proofMap[prf.TreeNode.ID] = prf.Proof
		case <-time.After(5 * time.Second):
			return errors.New("timeout waiting for proofs")
		}
	}
	// Sort the proofs in order and use that as our final result.
	log.LLvl3(p.ServerIdentity(), "sending back final proof")
	p.FinalProof <- ShuffleReply{sortProofs(proofMap, p.Root())}
	return nil
}

func splitPairs(pairs []ElGamalPair) ([]kyber.Point, []kyber.Point) {
	xs := make([]kyber.Point, len(pairs))
	ys := make([]kyber.Point, len(pairs))
	for i := range pairs {
		xs[i] = pairs[i].C1
		ys[i] = pairs[i].C2
	}
	return xs, ys
}

func combinePairs(xs, ys []kyber.Point) []ElGamalPair {
	if len(xs) != len(ys) {
		panic("slices have different lengths")
	}
	pairs := make([]ElGamalPair, len(xs))
	for i := range xs {
		pairs[i] = ElGamalPair{xs[i], ys[i]}
	}
	return pairs
}

func sortProofs(proofs map[onet.TreeNodeID]Proof, root *onet.TreeNode) []Proof {
	out := make([]Proof, len(proofs))
	curr := root
	var i int
	for curr != nil {
		out[i] = proofs[curr.ID]
		i++
		if len(curr.Children) == 0 {
			curr = nil
		} else {
			curr = curr.Children[0]
		}
	}
	return out
}

func treeIsChain(start *onet.TreeNode, n int) bool {
	var cnt int
	curr := start
	for curr != nil {
		cnt++
		if len(curr.Children) == 1 {
			curr = curr.Children[0]
		} else {
			curr = nil
		}
	}
	if cnt == n {
		return true
	}
	return false
}
