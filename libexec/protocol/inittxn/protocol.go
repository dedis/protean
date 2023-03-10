package inittxn

import (
	"bytes"
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(ProtoName, NewInitTxn)
}

type InitTxn struct {
	*onet.TreeNodeInstance

	Input        *base.InitTxnInput
	GeneratePlan GenerateFn
	KP           *key.Pair
	Publics      []kyber.Point

	Threshold      int
	Executed       chan bool
	Plan           *core.ExecutionPlan
	FinalSignature []byte // final signature that is sent back to client

	suite     *pairing.SuiteBn256
	failures  int
	responses []*Response
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewInitTxn(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	p := &InitTxn{
		TreeNodeInstance: n,
		Executed:         make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := p.RegisterHandlers(p.execute, p.executeResponse)
	if err != nil {
		return nil, xerrors.Errorf("couldn't register handlers: %v" + err.Error())
	}
	return p, nil
}

func (p *InitTxn) Start() error {
	var err error
	if p.Input == nil {
		p.finish(false)
		return xerrors.New("protocol did not receive verification data")
	}
	if p.GeneratePlan == nil {
		p.finish(false)
		return xerrors.New("verification function cannot be nil")
	}
	p.timeout = time.AfterFunc(5*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	p.Plan, err = p.GeneratePlan(p.Input)
	if err != nil {
		p.finish(false)
		return xerrors.Errorf("generating execution plan: %v", err)
	}
	planHash := p.Plan.Hash()
	resp, err := p.makeResponse(planHash)
	if err != nil {
		log.Errorf("%s couldn't generate response: %v", p.Name(), err)
		p.finish(false)
		return err
	}
	p.responses = append(p.responses, resp)
	p.mask, err = sign.NewMask(p.suite, p.Publics, p.KP.Public)
	if err != nil {
		log.Errorf("couldn't create the mask: %v", err)
		p.finish(false)
		return err
	}
	req := &Request{
		Input: p.Input,
		Data:  planHash,
	}
	errs := p.Broadcast(req)
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *InitTxn) execute(r StructRequest) error {
	defer p.Done()
	plan, err := p.GeneratePlan(r.Input)
	if err != nil {
		log.Lvl2(p.ServerIdentity(), "refused to return execution plan")
		return cothority.ErrorOrNil(p.SendToParent(&Response{}),
			"sending Response to parent")
	}
	planHash := plan.Hash()
	if !bytes.Equal(planHash, r.Data) {
		log.Lvl2(p.ServerIdentity(), "generated execution plan does not match parent's execution plan")
		return cothority.ErrorOrNil(p.SendToParent(&Response{}),
			"sending Response to parent")
	}
	resp, err := p.makeResponse(r.Data)
	if err != nil {
		log.Lvlf2("%s failed to prepare response: %v", p.ServerIdentity(), err)
	}
	return cothority.ErrorOrNil(p.SendToParent(resp),
		"sending Response to parent")
}

func (p *InitTxn) executeResponse(r StructResponse) error {
	index := utils.SearchPublicKey(p.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signature) == 0 || index < 0 {
		p.failures++
		if p.failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(p.ServerIdentity, "couldn't get enough shares")
			p.finish(false)
		}
		return nil
	}

	p.mask.SetBit(index, true)
	p.responses = append(p.responses, &r.Response)
	if len(p.responses) == p.Threshold {
		finalSignature := p.suite.G1().Point()
		for _, resp := range p.responses {
			sig, err := resp.Signature.Point(p.suite)
			if err != nil {
				p.finish(false)
				return err
			}
			finalSignature = finalSignature.Add(finalSignature, sig)
		}
		sig, err := finalSignature.MarshalBinary()
		if err != nil {
			p.finish(false)
			return err
		}
		p.FinalSignature = append(sig, p.mask.Mask()...)
		p.finish(true)
	}
	return nil
}

func (p *InitTxn) makeResponse(data []byte) (*Response, error) {
	sig, err := bls.Sign(p.suite, p.KP.Private, data)
	if err != nil {
		return &Response{}, err
	}
	return &Response{Signature: sig}, nil
}

func (p *InitTxn) finish(result bool) {
	p.timeout.Stop()
	select {
	case p.Executed <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	p.doneOnce.Do(func() { p.Done() })
}
