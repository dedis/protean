package verify

import (
	"bytes"
	"github.com/dedis/protean/core"
	"go.dedis.ch/cothority/v3"
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

	UpdateVer UpdateVerification
	Threshold int
	Verified  chan bool
	failures  int
	replies   []VResponse

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
	err := p.verifyExecutionRequest()
	if err != nil {
		log.Errorf("%s cannot verify the execution request: %v",
			p.ServerIdentity(), err)
		p.finish(false)
		return err
	}
	if p.UpdateVer != nil {
		if !p.UpdateVer(p.ExecRequest.EP.CID, p.ExecRequest.EP.StateRoot) {
			p.finish(false)
			return xerrors.New("cannot verify update")
		}
	}
	vr := &VRequest{
		ExecReq:      *p.ExecRequest,
		OpcodeHashes: p.OpcodeHashes,
		KVMap:        p.KVMap,
		UID:          p.UID,
		SUID:         p.SUID,
		OpcodeName:   p.OpcodeName,
		CEUID:        p.CEUID,
	}
	p.timeout = time.AfterFunc(1*time.Minute, func() {
		log.Lvl1("protocol timeout")
		p.finish(false)
	})
	errs := p.Broadcast(vr)
	if len(errs) > (len(p.Roster().List) - p.Threshold) {
		log.Errorf("Some nodes failed with error(s) %v", errs)
		return xerrors.New("too many nodes failed in broadcast")
	}
	return nil
}

func (p *VP) verify(r StructVRequest) error {
	defer p.Done()
	err := p.verifyExecutionRequest()
	if err != nil {
		log.Errorf("%s cannot verify the execution request: %v",
			p.ServerIdentity(), err)
		return cothority.ErrorOrNil(p.SendToParent(&VResponse{Success: false}),
			"sending VResponse to parent")
	}
	if p.UpdateVer != nil {
		if !p.UpdateVer(p.ExecRequest.EP.CID, p.ExecRequest.EP.StateRoot) {
			log.Errorf("%s cannot verify the execution request: %v",
				p.ServerIdentity())
			return cothority.ErrorOrNil(p.SendToParent(&VResponse{Success: false}),
				"sending VResponse to parent")
		}
	}
	return p.SendToParent(&VResponse{Success: true})
}

func (p *VP) verifyReply(r StructVResponse) error {
	if r.Success == false {
		log.Lvl2("Node", r.ServerIdentity, "failed verificiation")
		p.failures++
		if p.failures > len(p.Roster().List)-p.Threshold {
			log.Lvl2(p.ServerIdentity, "could not get enough success messages")
			p.finish(false)
		}
		return nil
	}
	p.replies = append(p.replies, r.VResponse)
	if len(p.replies) >= (p.Threshold - 1) {
		p.finish(true)
	}
	return nil
}

func (p *VP) verifyExecutionRequest() error {
	// Index of this opcode
	idx := p.ExecRequest.Index
	// 1) Check that the DFUID and opcode name are correct
	opcode := p.ExecRequest.EP.Txn.Opcodes[idx]
	if strings.Compare(p.UID, opcode.DFUID) != 0 {
		return xerrors.Errorf("Invalid UID. Expected %s but received %s", opcode.DFUID, p.UID)
	}
	if strings.Compare(p.OpcodeName, opcode.Name) != 0 {
		return xerrors.Errorf("Invalid opcode. Expected %s but received %s", opcode.Name, p.OpcodeName)
	}
	// 2) Check CEU's signature on the execution plan
	ceuData := p.ExecRequest.EP.DFUData[p.CEUID]
	epHash := p.ExecRequest.EP.Hash()
	err := p.ExecRequest.EPSig.VerifyWithPolicy(suite, epHash, ceuData.Keys,
		sign.NewThresholdPolicy(ceuData.Threshold))
	if err != nil {
		return xerrors.Errorf("cannot verify signature on the execution plan: %v", err)
	}
	// 3) Check dependencies
	for inputName, dep := range opcode.Dependencies {
		if dep.Src == core.OPCODE {
			//receipt, ok := p.ExecRequest.OpReceipts[dep.SrcName]
			receipt, ok := p.ExecRequest.OpReceipts[inputName]
			if !ok {
				return xerrors.Errorf("missing opcode receipt from output %s for input %s", dep.SrcName, inputName)
			}
			if strings.Compare(dep.SrcName, receipt.Name) != 0 {
				return xerrors.Errorf("expected src_name %s but received %s", dep.SrcName, receipt.Name)
			}
			if receipt.OpIdx != dep.Idx {
				return xerrors.Errorf("expected index %d but received %d", dep.Idx, receipt.OpIdx)
			}
			inputHash, ok := p.OpcodeHashes[inputName]
			if !ok {
				return xerrors.Errorf("cannot find the input data for %s", inputName)
			}
			if !bytes.Equal(inputHash, receipt.Digest) {
				return xerrors.Errorf("hashes do not match for input %s", inputName)
			}
			hash := receipt.Hash()
			dfuid := p.ExecRequest.EP.Txn.Opcodes[dep.Idx].DFUID
			dfuData, ok := p.ExecRequest.EP.DFUData[dfuid]
			if !ok {
				return xerrors.Errorf("cannot find dfu info for %s", dfuid)
			}
			err := receipt.Sig.VerifyWithPolicy(suite, hash, dfuData.Keys,
				sign.NewThresholdPolicy(dfuData.Threshold))
			if err != nil {
				return xerrors.Errorf("cannot verify signature from %s for on opcode receipt: %v", err)
			}
		} else if dep.Src == core.KEYVALUE {
			rs, ok := p.KVMap[inputName]
			if !ok {
				return xerrors.Errorf("missing keyvalue for input %s", inputName)
			}
			if !bytes.Equal(rs.Root, p.ExecRequest.EP.StateRoot) {
				return xerrors.Errorf("merkle roots do not match")
			}
			hash := rs.Hash()
			suData := p.ExecRequest.EP.DFUData[p.SUID]
			err := rs.Sig.VerifyWithPolicy(suite, hash, suData.Keys,
				sign.NewThresholdPolicy(suData.Threshold))
			if err != nil {
				return xerrors.Errorf("cannot verify state unit's signature on keyvalue: %v", err)
			}
		} else {
			log.Lvl1("CONST input data")
		}
	}
	return nil
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
