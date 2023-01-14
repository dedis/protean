package protocol

import (
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(RSProtocol, NewReadState)
}

type ReadState struct {
	*onet.TreeNodeInstance
	//Client     *byzcoin.Client
	CID        byzcoin.InstanceID
	SP         *core.StateProof
	ProofBytes []byte
	Keys       []string
	Threshold  int
	Executed   chan bool

	// Verification is only done by the leaf nodes. It checks that the root and
	// the leaf nodes have consistent Byzcoin proofs.
	Verify VerifyRSRequest

	ReadState      *core.ReadState
	FinalSignature []byte // final signature that is sent back to client

	suite     *pairing.SuiteBn256
	failures  int
	responses []GCSResponse
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
	if p.ProofBytes == nil {
		return xerrors.New("protocol did not receive message")
	}
	resp, err := p.makeResponse()
	if err != nil {
		log.Errorf("%s failed preparing response: %v", p.ServerIdentity(), err)
		p.finish(false)
		return err
	} else {
		p.mask, err = sign.NewMask(p.suite, p.Publics(), p.Public())
		if err != nil {
			log.Errorf("%s failed generating mask: %v", p.ServerIdentity(), err)
			p.finish(false)
			return err
		} else {
			p.responses = append(p.responses, *resp)
		}
	}
	req := &GCSRequest{
		CID:        p.CID,
		ProofBytes: p.ProofBytes,
		Keys:       p.Keys,
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	errs := p.Broadcast(req)
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *ReadState) execute(r StructGCSRequest) error {
	defer p.Done()
	p.SP = &core.StateProof{}
	if p.Verify != nil {
		if !p.Verify(r.GCSRequest.CID, r.GCSRequest.ProofBytes, p.SP) {
			log.Lvl2(p.ServerIdentity(), "refused to return read state")
			return cothority.ErrorOrNil(p.SendToParent(&GCSResponse{}),
				"sending GCSResponse to parent")
		}
	}
	p.ReadState = &core.ReadState{}
	resp, err := p.makeResponse()
	if err != nil {
		log.Lvlf2("%s failed preparing response: %v",
			p.ServerIdentity(), err)
		return cothority.ErrorOrNil(p.SendToParent(&GCSResponse{}),
			"sending empty GCSResponse to parent")
	}
	return cothority.ErrorOrNil(p.SendToParent(resp),
		"sending GCSResponse to parent")
}

func (p *ReadState) executeReply(r StructGCSResponse) error {
	if len(r.Signature) == 0 {
		p.failures++
		if p.failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(p.ServerIdentity, "couldn't get enough shares")
			p.finish(false)
		}
		return nil
	} else {
		_, index := getPublicKey(p.TreeNodeInstance, r.ServerIdentity)
		p.mask.SetBit(index, true)
		p.responses = append(p.responses, r.GCSResponse)
	}
	if len(p.responses) >= (p.Threshold - 1) {
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

func (p *ReadState) prepareKVDict(sp *core.StateProof, rs *core.ReadState) error {
	v, _, _, err := sp.Proof.Get(p.CID.Slice())
	if err != nil {
		return xerrors.Errorf("cannot get data from state proof: %v", err)
	}
	store := contracts.Storage{}
	err = protobuf.Decode(v, &store)
	if err != nil {
		return xerrors.Errorf("cannot decode state contract storage: %v", err)
	}
	kvStore := core.KVDict{}
	err = protobuf.Decode(store.Store[1].Value, &kvStore)
	if err != nil {
		return xerrors.Errorf("cannot decode kvstore: %v", err)
	}
	for _, key := range p.Keys {
		val, ok := kvStore.Data[key]
		if !ok {
			return xerrors.Errorf("missing key %s when preparing KVDict", key)
		}
		rs.KV.Data[key] = val
	}
	return nil
}

func (p *ReadState) makeResponse() (*GCSResponse, error) {
	err := p.prepareKVDict(p.SP, p.ReadState)
	if err != nil {
		return nil, xerrors.Errorf("failed creating the KV dict: %v", err)
	}
	p.ReadState.Root = p.SP.Proof.InclusionProof.GetRoot()
	hash := p.ReadState.Hash()
	sig, err := bls.Sign(p.suite, p.Private(), hash)
	if err != nil {
		return nil, xerrors.Errorf("failed generating bls signature: %v", err)
	}
	return &GCSResponse{Signature: sig}, nil
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
