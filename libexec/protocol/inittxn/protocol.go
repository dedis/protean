package inittxn

import (
	"bytes"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/util/key"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(ProtoName, NewInitTxn)
}

type InitTxn struct {
	*onet.TreeNodeInstance

	GeneratePlan     GenerateFn
	VerificationData []byte
	KP               *key.Pair
	Publics          []kyber.Point

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
	if p.VerificationData == nil {
		p.finish(false)
		return xerrors.New("protocol did not receive verification data")
	}
	if p.GeneratePlan == nil {
		p.finish(false)
		return xerrors.New("verification function cannot be nil")
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	plan, err := p.GeneratePlan(p.VerificationData)
	if err != nil {
		p.finish(false)
		return xerrors.Errorf("generating execution plan: %v", err)
	}
	planHash := plan.Hash()
	resp, err := p.makeResponse(planHash)
	if err != nil {
		log.Errorf("%s couldn't generate response: %v", p.Name(), err)
		p.finish(false)
		return err
	}
	p.responses = append(p.responses, resp)
	//p.mask, err = sign.NewMask(p.suite, p.Publics(), p.Public())
	p.mask, err = sign.NewMask(p.suite, p.Publics, p.KP.Public)
	if err != nil {
		log.Errorf("couldn't create the mask: %v", err)
		p.finish(false)
		return err
	}
	//var pk kyber.Point
	//own, err := p.makeResponse(planHash)
	//if err != nil {
	//	p.failures++
	//} else {
	//	p.responses = append(p.responses, *own)
	//	pk = p.Public()
	//}
	//p.mask, err = sign.NewMask(p.suite, p.Publics(), pk)
	//if err != nil {
	//	p.finish(false)
	//	return err
	//}
	p.Plan = plan
	req := &Request{
		Data:             planHash,
		VerificationData: p.VerificationData,
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
	plan, err := p.GeneratePlan(r.VerificationData)
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
		//return cothority.ErrorOrNil(p.SendToParent(&Response{}),
		//	"sending empty Response to parent")
	}
	return cothority.ErrorOrNil(p.SendToParent(resp),
		"sending Response to parent")
}

func (p *InitTxn) executeResponse(r StructResponse) error {
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
	//sig, err := bls.Sign(p.suite, p.Private(), data)
	sig, err := bls.Sign(p.suite, p.KP.Private, data)
	if err != nil {
		return &Response{}, err
	}
	return &Response{Signature: sig}, nil
}

func searchPublicKey(p *onet.TreeNodeInstance,
	servID *network.ServerIdentity) int {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return idx
		}
	}
	return -1
}

//func verifyInitTxn(data []byte) (*core.DFURegistry, *core.ContractHeader, error) {
//	var vData VerificationData
//	err := protobuf.Decode(data, &vData)
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot decode verification data: %v", err)
//	}
//	// Verify Byzcoin proofs
//	err = vData.RegistryProof.VerifyFromBlock(&vData.RegistryGenesis)
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot verify byzcoin proof (registry): %v", err)
//	}
//	err = vData.StateProof.Proof.VerifyFromBlock(&vData.StateGenesis)
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot verify byzcoin proof (registry): %v", err)
//	}
//	// Get registry data
//	v, _, _, err := vData.RegistryProof.Get(vData.RID.Slice())
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot get data from registry proof: %v", err)
//	}
//	store := contracts.Storage{}
//	err = protobuf.Decode(v, store)
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot decode registry contract storage: %v", err)
//	}
//	registry := &core.DFURegistry{}
//	err = protobuf.Decode(store.Store[0].Value, registry)
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot decode registry data: %v", err)
//	}
//	// Get contract header
//	v, _, _, err = vData.StateProof.Proof.Get(vData.CID.Slice())
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot get data from state proof: %v", err)
//	}
//	store = contracts.Storage{}
//	err = protobuf.Decode(v, store)
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot decode state contract storage: %v", err)
//	}
//	header := &core.ContractHeader{}
//	err = protobuf.Decode(store.Store[0].Value, header)
//	if err != nil {
//		return nil, nil, xerrors.Errorf("cannot decode contract header: %v", err)
//	}
//	// Check if CIDs match
//	if !header.CID.Equal(vData.CID) {
//		return nil, nil, xerrors.New("contract IDs do not match")
//	}
//	// Check that this txn can be executed in the curr_state
//	transition, ok := header.FSM.Transitions[vData.TxnName]
//	if !ok {
//		return nil, nil, xerrors.New("invalid txn name")
//	}
//	if transition.From != header.CurrState {
//		return nil, nil, xerrors.Errorf("cannot execute txn %s in curr_state %s",
//			vData.TxnName, header.CurrState)
//	}
//	// TODO: Check H(code)
//	return registry, header, nil
//}

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
