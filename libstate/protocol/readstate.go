package protocol

import (
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
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

func init() {
	onet.GlobalProtocolRegister(NameReadState, NewReadState)
}

type ReadState struct {
	*onet.TreeNodeInstance
	Client    *byzcoin.Client
	CID       byzcoin.InstanceID
	Data      []byte
	Threshold int
	Executed  chan bool

	Verify VerifyRSRequest

	FinalSignature []byte // final signature that is sent back to client

	suite     *pairing.SuiteBn256
	failures  int
	responses []GSResponse
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewReadState(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	p := &ReadState{
		TreeNodeInstance: n,
		Executed:         make(chan bool, 1),
		suite:            pairing.NewSuiteBn256(),
	}
	err := p.RegisterHandlers(p.execute, p.executeReply)
	if err != nil {
		return nil, xerrors.Errorf("couldn't register handlers: %v" + err.Error())
	}
	return p, nil
}

func (p *ReadState) Start() error {
	if p.Data == nil {
		return xerrors.New("protocol did not receive message")
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	var myKey kyber.Point
	own, err := p.makeResponse(p.Data)
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
	req := &GSRequest{
		CID:  p.CID,
		Data: p.Data,
	}
	errs := p.Broadcast(req)
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *ReadState) execute(r StructGSRequest) error {
	defer p.Done()
	if p.Verify != nil {
		if !p.Verify(r.GSRequest.CID, r.GSRequest.Data) {
			log.Lvl2(p.ServerIdentity(), "refused to return read state")
			return cothority.ErrorOrNil(p.SendToParent(&GSResponse{}),
				"sending GSResponse to parent")
		}
	}
	resp, err := p.makeResponse(r.GSRequest.Data)
	if err != nil {
		log.Lvlf2("%s failed preparing response: %v",
			p.ServerIdentity(), err)
		return cothority.ErrorOrNil(p.SendToParent(&GSResponse{}),
			"sending empty GSResponse to parent")
	}
	return cothority.ErrorOrNil(p.SendToParent(resp),
		"sending GSResponse to parent")
}

func (p *ReadState) executeReply(r StructGSResponse) error {
	if len(r.Signature) == 0 {
		p.failures++
		if p.failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(r.ServerIdentity, "couldn't get enough shares")
			p.finish(false)
		}
		return nil
	} else {
		_, index := getPublicKey(p.TreeNodeInstance, r.ServerIdentity)
		p.mask.SetBit(index, true)
		p.responses = append(p.responses, r.GSResponse)
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

func (p *ReadState) makeResponse(data []byte) (*GSResponse, error) {
	sig, err := bls.Sign(p.suite, p.Private(), data)
	if err != nil {
		return nil, err
	}
	return &GSResponse{Signature: sig}, nil
}

func getPublicKey(p *onet.TreeNodeInstance, servID *network.ServerIdentity) (
	kyber.Point, int) {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return p.NodePublic(si), idx
		}
	}

	return nil, -1
}

func (p *ReadState) finish(result bool) {
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
