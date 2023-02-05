package protocol

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/easyrand/base"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"time"
)

// SignProtocol starts a threshold BLS signature protocol.
type SignProtocol struct {
	*onet.TreeNodeInstance
	Msg         []byte
	Input       *base.RandomnessInput
	ExecReq     *core.ExecutionRequest
	InputHashes map[string][]byte

	Threshold      int
	FinalSignature chan []byte

	initChan chan initChan
	sigChan  chan sigChan
	syncChan chan syncChan

	verifyRoundMsg func([]byte, uint64) error
	sk             *share.PriShare
	pk             *share.PubPoly
	suite          pairing.Suite
}

// NewSignProtocol initialises the structure for use in one round.
func NewSignProtocol(n *onet.TreeNodeInstance, vf func([]byte, uint64) error,
	sk *share.PriShare, pk *share.PubPoly, suite pairing.Suite) (onet.ProtocolInstance, error) {
	t := &SignProtocol{
		TreeNodeInstance: n,
		verifyRoundMsg:   vf,
		sk:               sk,
		pk:               pk,
		suite:            suite,
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
		return xerrors.New("empty message")
	}
	if p.ExecReq == nil {
		return xerrors.New("missing execution request")
	}
	err := p.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify request: %v", p.Name(), err)
		return err
	}
	log.Lvl3(p.ServerIdentity(), "starting")
	return p.fullBroadcast(&Init{p.Msg, p.Input, p.ExecReq})
}

// Dispatch implements the onet.ProtocolInstance interface.
func (p *SignProtocol) Dispatch() error {
	defer p.Done()
	var err error
	initMsg := <-p.initChan
	p.Input = initMsg.Input
	p.ExecReq = initMsg.ExecReq
	p.InputHashes, err = p.Input.PrepareInputHashes()
	if err != nil {
		log.Errorf("%s couldn't generate the input hashes: %v",
			p.ServerIdentity(), err)
		return err
	}
	err = p.runVerification()
	if err != nil {
		log.Errorf("%s couldn't verify the execution request: %v", p.Name(), err)
		return err
	}
	// If the above verification succeeds,
	// that means the round value passed by the client (
	// and the root) equals the constant value in the workflow
	if err := p.verifyRoundMsg(initMsg.Msg, initMsg.Input.Round); err != nil {
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
	finalSig, err := tbls.Recover(p.suite, p.pk, initMsg.Msg, sigs, p.Threshold, n)
	if err != nil {
		return err
	}
	log.Lvl3(p.ServerIdentity(), "recovered")
	if p.IsRoot() {
		for i := 0; i < n-1; i++ {
			select {
			case <-p.syncChan:
			case <-time.After(time.Second * 2):
				return xerrors.New("time out while synchronising")
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

func (p *SignProtocol) runVerification() error {
	vData := &core.VerificationData{
		UID:         base.UID,
		OpcodeName:  base.RAND,
		InputHashes: p.InputHashes,
	}
	err := p.ExecReq.Verify(vData)
	if err != nil {
		return xerrors.Errorf("failed to verify the execution request: %v", err)
	}
	return nil
}
