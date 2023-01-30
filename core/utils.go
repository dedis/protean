package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
	"sort"
	"strings"
)

type VerifyData struct {
	Suite      *pairing.SuiteBn256
	UID        string
	OpcodeName string
	SUID       string
	CEUID      string
	// Prepared by the root node. key: input variable,
	// value: H(output) from parent opcode.
	OpcodeHashes map[string][]byte
	// Prepared by the client. key: input variable.
	KVMap map[string]ReadState
}

func (r *ExecutionRequest) VerifyRequest(data *VerifyData) error {
	// Index of this opcode
	idx := r.Index
	// 1) Check that the DFUID and opcode name are correct
	opcode := r.EP.Txn.Opcodes[idx]
	if strings.Compare(data.UID, opcode.DFUID) != 0 {
		return xerrors.Errorf("Invalid UID. Expected %s but received %s",
			opcode.DFUID, data.UID)
	}
	if strings.Compare(data.OpcodeName, opcode.Name) != 0 {
		return xerrors.Errorf("Invalid opcode. Expected %s but received %s",
			opcode.Name, data.OpcodeName)
	}
	// 2) Check CEU's signature on the execution plan
	ceuData := r.EP.DFUData[data.CEUID]
	epHash := r.EP.Hash()
	err := r.EPSig.VerifyWithPolicy(data.Suite, epHash, ceuData.Keys,
		sign.NewThresholdPolicy(ceuData.Threshold))
	if err != nil {
		return xerrors.Errorf("cannot verify signature on the execution plan: %v", err)
	}
	// 3) Check dependencies
	for inputName, dep := range opcode.Dependencies {
		if dep.Src == OPCODE {
			//receipt, ok := r.OpReceipts[dep.SrcName]
			receipt, ok := r.OpReceipts[inputName]
			if !ok {
				return xerrors.Errorf("missing opcode receipt from output %s for input %s", dep.SrcName, inputName)
			}
			if strings.Compare(dep.SrcName, receipt.Name) != 0 {
				return xerrors.Errorf("expected src_name %s but received %s", dep.SrcName, receipt.Name)
			}
			if receipt.OpIdx != dep.Idx {
				return xerrors.Errorf("expected index %d but received %d", dep.Idx, receipt.OpIdx)
			}
			inputHash, ok := data.OpcodeHashes[inputName]
			if !ok {
				return xerrors.Errorf("cannot find the input data for %s", inputName)
			}
			if !bytes.Equal(inputHash, receipt.Digest) {
				return xerrors.Errorf("hashes do not match for input %s", inputName)
			}
			hash := receipt.Hash()
			dfuid := r.EP.Txn.Opcodes[dep.Idx].DFUID
			dfuData, ok := r.EP.DFUData[dfuid]
			if !ok {
				return xerrors.Errorf("cannot find dfu info for %s", dfuid)
			}
			err := receipt.Sig.VerifyWithPolicy(data.Suite, hash, dfuData.Keys,
				sign.NewThresholdPolicy(dfuData.Threshold))
			if err != nil {
				return xerrors.Errorf("cannot verify signature from %s for on opcode receipt: %v", err)
			}
		} else if dep.Src == KEYVALUE {
			rs, ok := data.KVMap[inputName]
			if !ok {
				return xerrors.Errorf("missing keyvalue for input %s", inputName)
			}
			if !bytes.Equal(rs.Root, r.EP.StateRoot) {
				return xerrors.Errorf("merkle roots do not match")
			}
			hash := rs.Hash()
			suData := r.EP.DFUData[data.SUID]
			err := rs.Sig.VerifyWithPolicy(data.Suite, hash, suData.Keys,
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

func (p *ExecutionPlan) Hash() []byte {
	h := sha256.New()
	// CID
	h.Sum(p.CID)
	// StateRoot
	h.Sum(p.StateRoot)
	// CodeHash
	h.Sum(p.CodeHash)
	// TxnName
	h.Sum([]byte(p.TxnName))

	// Serialize transaction
	for _, opcode := range p.Txn.Opcodes {
		h.Sum([]byte(opcode.Name))
		h.Sum([]byte(opcode.DFUID))

		sortedDeps := make([]string, len(opcode.Dependencies))
		i := 0
		for k := range opcode.Dependencies {
			sortedDeps[i] = k
			i++
		}
		sort.Strings(sortedDeps)
		b := make([]byte, 8)
		for _, k := range sortedDeps {
			dep := opcode.Dependencies[k]
			binary.LittleEndian.PutUint64(b, uint64(dep.Idx))
			h.Sum([]byte(k))
			h.Sum([]byte(dep.Src))
			h.Sum([]byte(dep.SrcName))
			h.Sum(b)
			h.Sum([]byte(dep.Value))
		}
	}

	// Serialize DFUData
	sortedID := make([]string, len(p.DFUData))
	i := 0
	for k := range p.DFUData {
		sortedID[i] = k
		i++
	}
	sort.Strings(sortedID)
	b := make([]byte, 8)
	for _, k := range sortedID {
		h.Sum([]byte(k))
		binary.LittleEndian.PutUint64(b, uint64(p.DFUData[k].Threshold))
		h.Sum(b)
		for _, pk := range p.DFUData[k].Keys {
			h.Sum([]byte(pk.String()))
		}
	}
	return h.Sum(nil)
}

func (p *ExecutionPlan) String() string {
	res := new(strings.Builder)
	res.WriteString("==== Execution plan ====\n")
	fmt.Fprintf(res, "-- CID: %x\n", p.CID)
	fmt.Fprintf(res, "-- Root: %x\n", p.StateRoot)
	fmt.Fprintf(res, "-- Code hash: %x\n", p.CodeHash)
	fmt.Fprintf(res, "-- Txn: %s\n", p.TxnName)
	fmt.Fprintf(res, "--- Opcodes ---\n")
	for _, op := range p.Txn.Opcodes {
		fmt.Fprintf(res, ">> Name: %s DFUID: %s\n", op.Name, op.DFUID)
	}
	fmt.Fprintf(res, "--- DFUs ---\n")
	for d := range p.DFUData {
		fmt.Fprintf(res, ">> %s\n", d)
	}
	return res.String()
}

func (r *OpcodeReceipt) Hash() []byte {
	h := sha256.New()
	// EPID
	h.Sum([]byte(r.EPID))
	// OpIdx
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(r.OpIdx))
	h.Sum(b)
	// Name
	h.Sum([]byte(r.Name))
	// Digest
	h.Sum(r.Digest)
	return h.Sum(nil)
}

func (rs *ReadState) Hash() []byte {
	h := sha256.New()
	// Root
	h.Sum(rs.Root)
	// Deterministically serialize KVDict
	sortedKVDict := make([]string, len(rs.KVDict.Data))
	i := 0
	for k := range rs.KVDict.Data {
		sortedKVDict[i] = k
		i++
	}
	sort.Strings(sortedKVDict)
	for _, key := range sortedKVDict {
		h.Sum([]byte(key))
		h.Sum(rs.KVDict.Data[key])
	}
	return h.Sum(nil)
}
