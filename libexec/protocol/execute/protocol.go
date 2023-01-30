package execute

import (
	"github.com/dedis/protean/libexec/commons"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
	"golang.org/x/xerrors"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(ProtoName, NewExecute)
}

type Execute struct {
	*onet.TreeNodeInstance

	Inputs []commons.Input
	ExecFn commons.ExecutionFn

	Threshold int
	Executed  chan bool
	suite     *pairing.SuiteBn256
	failures  int
	responses []Response
	mask      *sign.Mask
	timeout   *time.Timer
	doneOnce  sync.Once
}

func NewExecute(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	p := &Execute{
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

func (p *Execute) Start() error {

	return nil
}

func (p *Execute) execute(r StructRequest) error {

	return nil
}

func (p *Execute) executeResponse(r StructResponse) error {

	return nil
}

//func (p *Execute) makeResponse(data []byte) (*Response, error) {
//	sig, err := bls.Sign(p.suite, p.Private(), data)
//	if err != nil {
//		return nil, err
//	}
//	return &Response{Signature: sig}, nil
//}

func searchPublicKey(p *onet.TreeNodeInstance,
	servID *network.ServerIdentity) int {
	for idx, si := range p.Roster().List {
		if si.Equal(servID) {
			return idx
		}
	}
	return -1
}

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
