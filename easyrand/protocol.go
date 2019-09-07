package easyrand

import (
	"errors"
	"time"

	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// SignProtocol starts a threshold BLS signature protocol.
type SignProtocol struct {
	*onet.TreeNodeInstance
	Msg      []byte
	initChan chan initChan
	sigChan  chan sigChan
	syncChan chan syncChan

	verifyMesg func([]byte) error
	sk         *share.PriShare
	pk         *share.PubPoly
	suite      pairing.Suite
	threshold  int

	FinalSignature chan []byte
}

// Init initializes the message to sign.
type Init struct {
	Msg []byte
}
type initChan struct {
	*onet.TreeNode
	Init
}

// Sig contains the full signature.
type Sig struct {
	ThresholdSig []byte
}
type sigChan struct {
	*onet.TreeNode
	Sig
}

// Sync is a synchronisation message.
type Sync struct{}

type syncChan struct {
	*onet.TreeNode
	Sync
}

// NewSignProtocol initialises the structure for use in one round.
func NewSignProtocol(n *onet.TreeNodeInstance, vf func([]byte) error, sk *share.PriShare, pk *share.PubPoly, suite pairing.Suite) (onet.ProtocolInstance, error) {
	numNodes := len(n.Roster().List)
	t := &SignProtocol{
		TreeNodeInstance: n,
		verifyMesg:       vf,
		sk:               sk,
		pk:               pk,
		suite:            suite,
		threshold:        numNodes - (numNodes-1)/3,
		FinalSignature:   make(chan []byte, 1),
	}
	if err := t.RegisterChannels(&t.initChan, &t.sigChan, &t.syncChan); err != nil {
		return nil, err
	}
	return t, nil
}

// Start implements the onet.ProtocolInstance interface.
func (p *SignProtocol) Start() error {
	if len(p.Msg) == 0 {
		return errors.New("empty message")
	}
	log.Lvl3(p.ServerIdentity(), "starting")
	return p.fullBroadcast(&Init{p.Msg})
}

// Dispatch implements the onet.ProtocolInstance interface.
func (p *SignProtocol) Dispatch() error {
	defer p.Done()
	initMsg := <-p.initChan
	if err := p.verifyMesg(initMsg.Msg); err != nil {
		return err
	}
	log.Lvl3(p.ServerIdentity(), "signing")
	sig, err := tbls.Sign(p.suite, p.sk, initMsg.Msg)
	if err != nil {
		return err
	}
	if err := p.fullBroadcast(&Sig{sig}); err != nil {
		return err
	}
	log.Lvl3(p.ServerIdentity(), "waiting for all signatures")
	// TODO handle error threshold (same as DKG threshold)
	n := len(p.List())
	sigs := make([][]byte, n)
	for i := 0; i < n; i++ {
		sigMsg := <-p.sigChan
		sigs[i] = sigMsg.ThresholdSig
	}
	// TODO fix the threshold
	//finalSig, err := tbls.Recover(p.suite, p.pk, initMsg.Msg, sigs, n-1, n)
	finalSig, err := tbls.Recover(p.suite, p.pk, initMsg.Msg, sigs, p.threshold, n)
	if err != nil {
		return err
	}
	log.Lvl3(p.ServerIdentity(), "recovered")
	if p.IsRoot() {
		for i := 0; i < n-1; i++ {
			select {
			case <-p.syncChan:
			case <-time.After(time.Second):
				return errors.New("time out while synchronising")
			}
		}
		p.FinalSignature <- finalSig
		return nil
	}
	p.FinalSignature <- finalSig
	return p.SendTo(p.Root(), &Sync{})
}

func (p *SignProtocol) fullBroadcast(msg interface{}) error {
	n := len(p.List())
	errc := make(chan error, n)
	for _, treenode := range p.List() {
		go func(tn *onet.TreeNode) {
			errc <- p.SendTo(tn, msg)
		}(treenode)
	}
	// TODO handle error threshold
	for i := 0; i < len(p.List()); i++ {
		if err := <-errc; err != nil {
			return err
		}
	}
	return nil
}
