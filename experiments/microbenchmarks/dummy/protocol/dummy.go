package protocol

import (
	"sync"
	"time"

	"github.com/dedis/protean/utils"
	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

func init() {
	_, err := onet.GlobalProtocolRegister(DummyProtoName, NewDummy)
	if err != nil {
		log.Errorf("cannot register protocol: %v", err)
		panic(err)
	}
}

type Dummy struct {
	*onet.TreeNodeInstance
	OutputData map[string][]byte
	Threshold  int
	Failures   int
	Finished   chan bool
	responses  []*DummyResponse
	timeout    *time.Timer
	doneOnce   sync.Once
}

func NewDummy(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	rv := &Dummy{
		TreeNodeInstance: n,
		Finished:         make(chan bool, 1),
	}
	err := rv.RegisterHandlers(rv.dummy, rv.dummyResponse)
	if err != nil {
		return nil, err
	}
	return rv, nil
}

func (d *Dummy) Start() error {
	if d.OutputData == nil {
		d.finish(false)
		return xerrors.New("initialize OutputData first")
	}
	d.timeout = time.AfterFunc(5*time.Minute, func() {
		log.Lvl1("Dummy protocol timeout")
		d.finish(false)
	})
	errs := d.SendToChildrenInParallel(&DummyRequest{OutputData: d.OutputData})
	if len(errs) > (len(d.Roster().List) - d.Threshold) {
		log.Errorf("some nodes failed with error(s) %s", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (d *Dummy) dummy(r structDummy) error {
	defer d.Done()
	//d.OutputData = r.OutputData
	return cothority.ErrorOrNil(d.SendToParent(&DummyResponse{OK: true}),
		"sending DummyResponse to parent")
}

func (d *Dummy) dummyResponse(r structDummyResponse) error {
	index := utils.SearchPublicKey(d.TreeNodeInstance, r.ServerIdentity)
	if r.OK == false || index < 0 {
		log.Lvl2(r.ServerIdentity, "refused to respond")
		d.Failures++
		if d.Failures > (len(d.Roster().List) - d.Threshold) {
			log.Lvl2(d.ServerIdentity, "couldn't get enough responses")
			d.finish(false)
		}
		return nil
	}
	d.responses = append(d.responses, &r.DummyResponse)
	if len(d.responses) == d.Threshold {
		d.finish(true)
	}
	return nil
}

func (d *Dummy) finish(result bool) {
	d.timeout.Stop()
	select {
	case d.Finished <- result:
		// succeeded
	default:
		// would have blocked because some other call to finish()
		// beat us.
	}
	d.doneOnce.Do(func() { d.Done() })
}
