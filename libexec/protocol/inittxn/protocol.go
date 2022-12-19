package initTxn

import (
	"github.com/dedis/protean/core"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(Name, NewInitTxn)
}

type InitTxn struct {
	*onet.TreeNodeInstance

	Generate         GenerateFn
	VerificationData []byte

	Threshold      int
	Executed       chan bool
	FinalSignature []byte // final signature that is sent back to client

	suite    *pairing.SuiteBn256
	failures int
	//responses []GSResponse
	mask     *sign.Mask
	timeout  *time.Timer
	doneOnce sync.Once
}

func NewInitTxn(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	p := &InitTxn{
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

func (p *InitTxn) Start() error {
	if p.VerificationData == nil {
		p.finish(false)
		return xerrors.New("protocol did not receive verification data")
	}
	if p.Generate == nil {
		p.finish(false)
		return xerrors.New("verification function cannot be nil")
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	p.Generate(p.VerificationData)

	//registry, header, err := verifyInitTxn(p.VerificationData)
	//if err != nil {
	//	p.finish(false)
	//	return xerrors.Errorf("verification error - %v", err)
	//}
	//plan := &core.ExecutionPlan{}
	//generateExecutionPlan(plan, registry, header)
	return nil
}

func (p *InitTxn) execute() {}

func (p *InitTxn) executeReply() {}

func generateExecutionPlan(plan *core.ExecutionPlan, registry *core.DFURegistry,
	header *core.ContractHeader) {
	plan.CID = header.CID.Slice()
	plan.CodeHash = header.CodeHash

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
