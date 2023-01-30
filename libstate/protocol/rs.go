package protocol

import (
	"github.com/dedis/protean/contracts"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
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
	CID        byzcoin.InstanceID
	ProofBytes []byte
	ReqKeys    []string

	Threshold int
	Executed  chan bool

	// Verification is only done by the leaf nodes. It checks that the root and
	// the leaf nodes have consistent Byzcoin proofs.
	Verify VerifyRSRequest

	SP             *core.StateProof
	ReadState      *core.ReadState
	FinalSignature []byte // final signature that is sent back to client

	suite     *pairing.SuiteBn256
	failures  int
	responses []RSResponse
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
		return xerrors.New("protocol didn't receive message")
	}
	resp, err := p.makeResponse()
	if err != nil {
		log.Errorf("%s failed preparing response: %v", p.ServerIdentity(), err)
		p.finish(false)
		return err
	}
	p.mask, err = sign.NewMask(p.suite, p.Publics(), p.Public())
	if err != nil {
		log.Errorf("%s failed to generate mask: %v", p.ServerIdentity(), err)
		p.finish(false)
		return err
	}
	p.responses = append(p.responses, *resp)
	req := &RSRequest{
		CID:        p.CID,
		ProofBytes: p.ProofBytes,
		ReqKeys:    p.ReqKeys,
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	errs := p.Broadcast(req)
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *ReadState) execute(r StructRSRequest) error {
	defer p.Done()
	var err error
	p.SP, err = p.Verify(r.RSRequest.CID, r.RSRequest.ProofBytes)
	if err != nil {
		log.Lvl2(p.ServerIdentity(), "refused to return read state")
		return cothority.ErrorOrNil(p.SendToParent(&RSResponse{}),
			"sending RSResponse to parent")
	}
	resp, err := p.makeResponse()
	if err != nil {
		log.Lvlf2("%s failed preparing response: %v", p.ServerIdentity(), err)
		return cothority.ErrorOrNil(p.SendToParent(&RSResponse{}),
			"sending empty RSResponse to parent")
	}
	return cothority.ErrorOrNil(p.SendToParent(resp),
		"sending RSResponse to parent")
}

func (p *ReadState) executeReply(r StructRSResponse) error {
	index := searchPublicKey(p.TreeNodeInstance, r.ServerIdentity)
	if len(r.Signature) == 0 || index < 0 {
		p.failures++
		if p.failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(p.ServerIdentity, "couldn't get enough shares")
			p.finish(false)
		}
		return nil
	}

	p.mask.SetBit(index, true)
	p.responses = append(p.responses, r.RSResponse)

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

func (p *ReadState) prepareKVDict() error {
	v, _, _, err := p.SP.Proof.Get(p.CID.Slice())
	if err != nil {
		return xerrors.Errorf("cannot get data from state proof: %v", err)
	}
	store := contracts.Storage{}
	err = protobuf.Decode(v, &store)
	if err != nil {
		return xerrors.Errorf("cannot decode state contract storage: %v", err)
	}

	p.ReadState = &core.ReadState{}
	key2idx := make(map[string]int)
	// Skipping index 0 because that is header
	for i := 1; i < len(store.Store); i++ {
		key2idx[store.Store[i].Key] = i
	}
	for _, key := range p.ReqKeys {
		idx, ok := key2idx[key]
		if !ok {
			p.ReadState = nil
			return xerrors.Errorf("missing key %s when preparing kv dict", key)
		}
		p.ReadState.KVDict.Data[key] = store.Store[idx].Value
	}
	//kvStore := core.KVDict{}
	//err = protobuf.Decode(store.Store[1].Value, &kvStore)
	//if err != nil {
	//	return xerrors.Errorf("cannot decode kvstore: %v", err)
	//}
	//p.ReadState = &core.ReadState{}
	//for _, key := range p.Keys {
	//	val, ok := kvStore.Data[key]
	//	if !ok {
	//		return xerrors.Errorf("missing key %s when preparing KVDict", key)
	//	}
	//	p.ReadState.KVDict.Data[key] = val
	//}
	return nil
}

func (p *ReadState) makeResponse() (*RSResponse, error) {
	err := p.prepareKVDict()
	if err != nil {
		return nil, xerrors.Errorf("failed creating the KV dict: %v", err)
	}
	p.ReadState.Root = p.SP.Proof.InclusionProof.GetRoot()
	hash := p.ReadState.Hash()
	sig, err := bls.Sign(p.suite, p.Private(), hash)
	if err != nil {
		return nil, xerrors.Errorf("failed to generate the bls signature: %v", err)
	}
	return &RSResponse{Signature: sig}, nil
}

func searchPublicKey(p *onet.TreeNodeInstance, servID *network.ServerIdentity) int {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return idx
		}
	}
	return -1
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
