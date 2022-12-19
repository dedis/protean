package protocol

import (
	"fmt"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

// VerificationFn is called on every node. Where msg is the message that is
// co-signed and the data is additional data for verification.
type VerificationFn func(msg, data []byte) bool

func init() {
	onet.GlobalProtocolRegister(NameTestBlsCosi, NewBlsCosi)
}

type TestBlsCosi struct {
	*onet.TreeNodeInstance
	suite          *pairing.SuiteBn256
	Msg            []byte
	Threshold      int
	Executed       chan bool
	FinalSignature []byte // final signature that is sent back to client

	failures       int
	verificationFn VerificationFn
	responses      []Response
	mask           *sign.Mask
	timeout        *time.Timer
	doneOnce       sync.Once
}

func NewBlsCosi(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	c := &TestBlsCosi{
		TreeNodeInstance: n,
		Executed:         make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := c.RegisterHandlers(c.execute, c.executeReply)
	if err != nil {
		return nil, xerrors.Errorf("couldn't register handlers: %v" + err.Error())
	}
	return c, nil
}

func (p *TestBlsCosi) Start() error {
	if err := p.checkIntegrity(); err != nil {
		p.finish(false)
		return err
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})

	var myKey kyber.Point
	own, err := p.makeResponse()
	if err != nil {
		p.failures++
		myKey = nil
	} else {
		p.responses = append(p.responses, *own)
		myKey = p.Public()
	}
	p.mask, err = sign.NewMask(p.suite, p.Publics(), myKey)
	if err != nil {
		p.finish(false)
		return err
	}

	req := &Request{ReqData: p.Msg}
	errs := p.Broadcast(req)
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *TestBlsCosi) execute(r StructRequest) error {
	defer p.Done()
	// TODO: Run the verification function here. If we cannot verify,
	// return empty response
	p.Msg = r.ReqData
	resp, err := p.makeResponse()
	if err != nil {
		return cothority.ErrorOrNil(p.SendToParent(&Response{}),
			"sending Response to parent")
	}
	return cothority.ErrorOrNil(p.SendToParent(resp),
		"sending Response to parent")
}

func (p *TestBlsCosi) makeResponse() (*Response, error) {
	sig, err := bls.Sign(p.suite, p.Private(), p.Msg)
	if err != nil {
		return nil, err
	}
	return &Response{
		Data:      p.Msg,
		Signature: sig,
	}, nil
}

func (p *TestBlsCosi) executeReply(rr StructResponse) error {
	if len(rr.Signature) == 0 {
		p.failures++
		if p.failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(rr.ServerIdentity, "couldn't get enough shares")
			p.finish(false)
		}
		return nil
	} else {
		_, index := searchPublicKey(p.TreeNodeInstance, rr.ServerIdentity)
		p.mask.SetBit(index, true)
		p.responses = append(p.responses, rr.Response)
	}

	if len(p.responses) >= p.Threshold {
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

func (p *TestBlsCosi) checkIntegrity() error {
	if p.Msg == nil {
		return xerrors.New("subprotocol does not have a proposal msg")
	}
	//if p.verificationFn == nil {
	//	return xerrors.New("subprotocol has an empty verification fn")
	//}
	//if p.Timeout < 10*time.Nanosecond {
	//	return xerrors.New("unrealistic timeout")
	//}
	//if p.Threshold > p.Tree().Size() {
	//	return xerrors.New("threshold bigger than number of nodes in subtree")
	//}
	if p.Threshold < 1 {
		return fmt.Errorf("threshold of %d smaller than one node", p.Threshold)
	}
	return nil
}

func searchPublicKey(p *onet.TreeNodeInstance, servID *network.ServerIdentity) (kyber.Point, int) {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return p.NodePublic(si), idx
		}
	}

	return nil, -1
}

func (p *TestBlsCosi) finish(result bool) {
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
