package core

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
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
		for _, pk := range p.DFUData[k].Keys {
			h.Sum([]byte(pk.String()))
		}
	}
	return h.Sum(nil)
}
