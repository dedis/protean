package verify

import (
	"bytes"
	"github.com/dedis/protean/core"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"strings"
	"sync"
	"time"
)

func init() {
	onet.GlobalProtocolRegister(Name, NewVerify)
}

type VP struct {
	*onet.TreeNodeInstance
	ExecRequest *core.ExecutionRequest
	// Prepared by the root node. key: input variable,
	// value: H(output) from parent opcode.
	OpcodeHashes map[string][]byte
	// Prepared by the client. key: input variable.
	KVMap map[string]core.ReadState

	UID        string
	OpcodeName string
	SUID       string
	CEUID      string

	Threshold int
	Verified  chan bool
	failures  int

	timeout  *time.Timer
	doneOnce sync.Once
}

func NewVerify(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	p := &VP{
		TreeNodeInstance: n,
		Verified:         make(chan bool, 1),
	}
	err := p.RegisterHandlers(p.verify, p.verifyReply)
	if err != nil {
		return nil, xerrors.Errorf("couldn't register handlers: %v" + err.Error())
	}
	return p, nil
}

func (p *VP) Start() error {
	if p.ExecRequest == nil {
		p.finish(false)
		return xerrors.New("protocol did not receive execution request data")
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	vr := &VRequest{
		ExecReq:      *p.ExecRequest,
		OpcodeHashes: p.OpcodeHashes,
		KVMap:        p.KVMap,
		UID:          p.UID,
		SUID:         p.SUID,
		OpcodeName:   p.OpcodeName,
		CEUID:        p.CEUID,
	}
	errs := p.Broadcast(vr)
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *VP) verify(r StructVRequest) error {
	defer p.Done()
	return nil
}

func (p *VP) verifyReply(r StructVResponse) error {

	return nil
}

func (p *VP) verifyExecutionRequest() bool {
	// Index of this opcode
	idx := p.ExecRequest.Index
	// 1) Check that the DFUID and opcode name are correct
	opcode := p.ExecRequest.EP.Txn.Opcodes[idx]
	if strings.Compare(p.UID, opcode.DFUID) != 0 {
		log.Errorf("Invalid UID. Expected %s but received %s", opcode.DFUID, p.UID)
		return false
	}
	if strings.Compare(p.OpcodeName, opcode.Name) != 0 {
		log.Errorf("Invalid opcode. Expected %s but received %s", opcode.Name, p.OpcodeName)
		return false
	}
	// 2) Check CEU's signature on the execution plan
	ceuData := p.ExecRequest.EP.DFUData[p.CEUID]
	epHash := p.ExecRequest.EP.Hash()
	err := p.ExecRequest.EPSig.VerifyWithPolicy(suite, epHash, ceuData.Keys,
		sign.NewThresholdPolicy(ceuData.Threshold))
	if err != nil {
		log.Errorf("cannot verify signature on the execution plan: %v", err)
		return false
	}
	// 3) Check dependencies
	for inputName, dep := range opcode.Dependencies {
		if dep.Src == core.OPCODE {
			receipt, ok := p.ExecRequest.OpReceipts[dep.SrcName]
			if !ok {
				log.Errorf("input: %s - missing opcode receipt for src_name: %s", inputName, dep.SrcName)
				return false
			}
			if strings.Compare(dep.SrcName, receipt.Name) != 0 {
				log.Errorf("expected src_name %s but received %s",
					dep.SrcName, receipt.Name)
			}
			if receipt.OpIdx != dep.Idx {
				log.Errorf("expected index %d but received %d", dep.Idx,
					receipt.OpIdx)
				return false
			}
			inputHash, ok := p.OpcodeHashes[inputName]
			if !ok {
				log.Errorf("cannot find the input data for %s", inputName)
				return false
			}
			if !bytes.Equal(inputHash, receipt.Digest) {
				log.Errorf("hashes do not match for input %s", inputName)
				return false
			}
			hash := receipt.Hash()
			dfuid := p.ExecRequest.EP.Txn.Opcodes[dep.Idx].DFUID
			dfuData, ok := p.ExecRequest.EP.DFUData[dfuid]
			if !ok {
				log.Errorf("cannot find dfu info for %s", dfuid)
				return false
			}
			err := receipt.Sig.VerifyWithPolicy(suite, hash, dfuData.Keys,
				sign.NewThresholdPolicy(dfuData.Threshold))
			if err != nil {
				log.Errorf("cannot verify signature from %s for on opcode"+
					" receipt: %v", err)
				return false
			}
		} else if dep.Src == core.KEYVALUE {
			rs, ok := p.KVMap[inputName]
			if !ok {
				log.Errorf("missing keyvalue for input %s", inputName)
				return false
			}
			if !bytes.Equal(rs.Root, p.ExecRequest.EP.StateRoot) {
				log.Errorf("merkle roots do not match")
				return false
			}
			hash := rs.Hash()
			suData := p.ExecRequest.EP.DFUData[p.SUID]
			err := rs.Sig.VerifyWithPolicy(suite, hash, suData.Keys,
				sign.NewThresholdPolicy(suData.Threshold))
			if err != nil {
				log.Errorf("cannot verify state unit's signature on keyvalue: %v", err)
				return false
			}
		} else {
			log.Lvl1("CONST input data")
		}
	}
	return true
}

func (p *VP) finish(result bool) {
	p.timeout.Stop()
	select {
	case p.Verified <- result:
		// success
	default:
		// would have blocked because some other call to finish() beat us
	}
	p.doneOnce.Do(func() { p.Done() })
}
