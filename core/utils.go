package core

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

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
	sortedKVDict := make([]string, len(rs.KV.Data))
	i := 0
	for k := range rs.KV.Data {
		sortedKVDict[i] = k
		i++
	}
	sort.Strings(sortedKVDict)
	for _, key := range sortedKVDict {
		h.Sum([]byte(key))
		h.Sum(rs.KV.Data[key])
	}
	return h.Sum(nil)
}
