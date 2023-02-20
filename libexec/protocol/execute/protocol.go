package execute

import (
	"github.com/dedis/protean/core"
	"github.com/dedis/protean/libexec/base"
	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	blsproto "go.dedis.ch/cothority/v3/blscosi/protocol"
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
	onet.GlobalProtocolRegister(ProtoName, NewExecute)
}

type Execute struct {
	*onet.TreeNodeInstance

	FnName   string
	Input    *base.ExecuteInput
	Output   *base.ExecuteOutput
	ExecReq  *core.ExecutionRequest
	Receipts map[string]*core.OpcodeReceipt

	KP        *key.Pair
	Publics   []kyber.Point
	Threshold int
	Executed  chan bool

	outputHashes map[string][]byte

	suite     *pairing.SuiteBn256
	failures  int
	responses []*Response
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewExecute(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	p := &Execute{
		TreeNodeInstance: n,
		Executed:         make(chan bool, 1),
		Receipts:         make(map[string]*core.OpcodeReceipt),
		suite:            pairing.NewSuiteBn256(),
	}
	err := p.RegisterHandlers(p.execute, p.executeResponse)
	if err != nil {
		return nil, xerrors.Errorf("couldn't register handlers: %v" + err.Error())
	}
	return p, nil
}

func (p *Execute) Start() error {
	var err error
	if p.Input == nil {
		p.finish(false)
		return xerrors.New("missing input")
	}
	execFn, genInput, vdata, err := demuxRequest(p.FnName, p.Input)
	if err != nil {
		log.Errorf("%s failed to demux request: %v", p.Name(), err)
		p.finish(false)
		return err
	}
	err = p.ExecReq.Verify(vdata)
	if err != nil {
		log.Errorf("%s failed to verify the execution request: %v", p.Name(), err)
		p.finish(false)
		return err
	}
	genInput.KVDicts, err = core.PrepareKVDicts(p.ExecReq, p.Input.StateProofs)
	genericOut, err := execFn(genInput)
	if err != nil {
		log.Errorf("%s failed to execute function: %v", p.Name(), err)
		p.finish(false)
		return err
	}
	p.Output, p.outputHashes, err = muxRequest(p.FnName, genericOut)
	if err != nil {
		log.Errorf("%s failed to prepare output: %v", p.Name(), err)
		p.finish(false)
		return err
	}
	resp, err := p.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response:% v", p.Name(), err)
		p.finish(false)
		return err
	}
	p.responses = append(p.responses, resp)
	//p.mask, err = sign.NewMask(p.suite, p.Publics(), p.Public())
	p.mask, err = sign.NewMask(p.suite, p.Publics, p.KP.Public)
	if err != nil {
		p.finish(false)
		return xerrors.Errorf("couldn't generate mask: %v", err)
	}
	p.timeout = time.AfterFunc(2*time.Minute, func() {
		log.Lvl1("execute protocol timeout")
		p.finish(false)
	})
	errs := p.Broadcast(&Request{FnName: p.FnName, Input: p.Input, ExecReq: p.ExecReq})
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *Execute) execute(r StructRequest) error {
	defer p.Done()
	p.Input = r.Input
	p.ExecReq = r.ExecReq
	execFn, genInput, vdata, err := demuxRequest(r.FnName, p.Input)
	if err != nil {
		log.Errorf("%s failed to demux request: %v", p.Name(), err)
		return cothority.ErrorOrNil(p.SendToParent(&Response{}),
			"sending Response to parent")
	}
	err = p.ExecReq.Verify(vdata)
	if err != nil {
		log.Errorf("%s failed to verify the execution request: %v", p.Name(), err)
		return cothority.ErrorOrNil(p.SendToParent(&Response{}),
			"sending Response to parent")
	}
	genInput.KVDicts, err = core.PrepareKVDicts(p.ExecReq, p.Input.StateProofs)
	genericOut, err := execFn(genInput)
	if err != nil {
		log.Errorf("%s failed to execute function: %v", p.Name(), err)
		p.finish(false)
		return err
	}
	p.Output, p.outputHashes, err = muxRequest(r.FnName, genericOut)
	if err != nil {
		log.Errorf("%s failed to prepare output: %v:", p.Name(), err)
		return cothority.ErrorOrNil(p.SendToParent(&Response{}),
			"sending Response to parent")
	}
	resp, err := p.generateResponse()
	if err != nil {
		log.Errorf("%s failed to generate response: %v", p.Name(), err)
	}
	return cothority.ErrorOrNil(p.SendToParent(resp),
		"sending Response to parent")
}

func (p *Execute) executeResponse(r StructResponse) error {
	index := utils.SearchPublicKey(p.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signatures) == 0 || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		p.failures++
		if p.failures > (len(p.Roster().List) - p.Threshold) {
			log.Lvl2(p.ServerIdentity, "couldn't get enough responses")
			p.finish(false)
		}
		return nil
	}

	p.mask.SetBit(index, true)
	p.responses = append(p.responses, &r.Response)
	if len(p.responses) == p.Threshold {
		for name, receipt := range p.Receipts {
			aggSignature := p.suite.G1().Point()
			for _, resp := range p.responses {
				sig, err := resp.Signatures[name].Point(p.suite)
				if err != nil {
					p.finish(false)
					return err
				}
				aggSignature = aggSignature.Add(aggSignature, sig)
			}
			sig, err := aggSignature.MarshalBinary()
			if err != nil {
				p.finish(false)
				return err
			}
			// Add aggregated BLS signature to the receipt
			receipt.Sig = append(sig, p.mask.Mask()...)
		}
		p.finish(true)
	}
	return nil
}

func (p *Execute) generateResponse() (*Response, error) {
	sigs := make(map[string]blsproto.BlsSignature)
	for outputName, outputHash := range p.outputHashes {
		r := core.OpcodeReceipt{
			EPID:      p.ExecReq.EP.Hash(),
			OpIdx:     p.ExecReq.Index,
			Name:      outputName,
			HashBytes: outputHash,
		}
		sig, err := bls.Sign(p.suite, p.KP.Private, r.Hash())
		if err != nil {
			return &Response{}, err
		}
		sigs[outputName] = sig
		if p.IsRoot() {
			p.Receipts[outputName] = &r
		}
	}
	return &Response{Signatures: sigs}, nil
}

//func (p *Execute) runVerification(hashes map[string][]byte, precmts *core.KVDict) error {
//	vData := &core.VerificationData{
//		UID:         base.UID,
//		OpcodeName:  base.EXEC,
//		InputHashes: hashes,
//		Precommits:  precmts,
//	}
//	return p.ExecReq.Verify(vData)
//}

func (p *Execute) finish(result bool) {
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
