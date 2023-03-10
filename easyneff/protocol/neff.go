package protocol

import (
	"time"

	"github.com/dedis/protean/easyneff/base"
	"golang.org/x/xerrors"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/kyber/v3/sign/schnorr"
	"go.dedis.ch/onet/v3"
)

// NeffShuffle is a protocol for running the Neff shuffle in a chain.
type NeffShuffle struct {
	*onet.TreeNodeInstance

	ShufInput  *base.ShuffleInput
	FinalProof chan base.ShuffleOutput

	suite     proof.Suite
	reqChan   chan reqChan
	proofChan chan proofChan
}

type reqChan struct {
	*onet.TreeNode
	Request
}

type proofChan struct {
	*onet.TreeNode
	base.Proof
}

// NewShuffleProtocol initializes the shuffle protocol, it is used as a
// callback when creating new shuffle protocol instances.
func NewShuffleProtocol(n *onet.TreeNodeInstance, suite proof.Suite) (onet.ProtocolInstance, error) {
	p := &NeffShuffle{
		TreeNodeInstance: n,
		FinalProof:       make(chan base.ShuffleOutput, 1),
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
func (p *NeffShuffle) Start() error {
	if !p.IsRoot() {
		return xerrors.New("protocol must start on root")
	}
	if !treeIsChain(p.Root(), len(p.List())) {
		return xerrors.New("tree must be a line")
	}
	// start the shuffle
	return p.SendTo(p.Root(), &Request{ShuffleInput: p.ShufInput})
}

// Dispatch implements the onet.ProtocolInstance interface.
func (p *NeffShuffle) Dispatch() error {
	defer p.Done()
	// handle the first request
	req := <-p.reqChan
	p.ShufInput = req.ShuffleInput
	X, Y := splitPairs(p.ShufInput.Pairs)
	Xbar, Ybar, prover := shuffle.Shuffle(p.suite, nil, p.ShufInput.H, X, Y,
		p.suite.RandomStream())
	prf, err := proof.HashProve(p.suite, "", prover)
	if err != nil {
		return err
	}

	// sign it and reply to the root and send it to the next node
	sig, err := schnorr.Sign(p.suite, p.Private(), prf)
	if err != nil {
		return err
	}
	signedPrf := base.Proof{
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
	newReq := Request{
		ShuffleInput: &base.ShuffleInput{
			Pairs: signedPrf.Pairs,
			H:     p.ShufInput.H,
		},
	}
	if err := p.SendTo(p.Children()[0], &newReq); err != nil {
		return err
	}
	// No need to collect other proof if I'm not the root.
	if !p.IsRoot() {
		return nil
	}
	proofMap := make(map[onet.TreeNodeID]base.Proof)
	for i := 0; i < len(p.List()); i++ {
		select {
		case prf := <-p.proofChan:
			proofMap[prf.TreeNode.ID] = prf.Proof
		case <-time.After(15 * time.Minute):
			return xerrors.New("timeout waiting for proofs")
		}
	}
	// Sort the proofs in order and use that as our final result.
	p.FinalProof <- base.ShuffleOutput{Proofs: sortProofs(proofMap, p.Root())}
	return nil
}

func splitPairs(pairs utils.ElGamalPairs) ([]kyber.Point, []kyber.Point) {
	ps := pairs.Pairs
	xs := make([]kyber.Point, len(ps))
	ys := make([]kyber.Point, len(ps))
	for i := range ps {
		xs[i] = ps[i].K
		ys[i] = ps[i].C
	}
	return xs, ys
}

func combinePairs(xs, ys []kyber.Point) utils.ElGamalPairs {
	if len(xs) != len(ys) {
		panic("slices have different lengths")
	}
	pairs := make([]utils.ElGamalPair, len(xs))
	for i := range xs {
		pairs[i] = utils.ElGamalPair{K: xs[i], C: ys[i]}
	}
	return utils.ElGamalPairs{Pairs: pairs}
}

func sortProofs(proofs map[onet.TreeNodeID]base.Proof, root *onet.TreeNode) []base.Proof {
	out := make([]base.Proof, len(proofs))
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
