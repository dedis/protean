package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"github.com/dedis/protean/contracts"
	"sort"
	"strings"

	"go.dedis.ch/cothority/v3"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing"
	"go.dedis.ch/kyber/v3/sign"
	"go.dedis.ch/protobuf"
	"golang.org/x/xerrors"
)

var suite = pairing.NewSuiteBn256()

type VerificationData struct {
	UID        string
	OpcodeName string
	// key: input variable, value: H(output) from parent opcode.
	InputHashes map[string][]byte
	StateProofs map[string]*StateProof
	Precommits  *KVDict
}

func (r *ExecutionRequest) Verify(data *VerificationData) error {
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
	ceuData := r.EP.DFUData[CEUID]
	epHash := r.EP.Hash()
	err := r.EP.Sig.VerifyWithPolicy(suite, epHash, ceuData.Keys,
		sign.NewThresholdPolicy(ceuData.Threshold))
	if err != nil {
		return xerrors.Errorf("cannot verify signature on the execution plan: %v", err)
	}
	// 3) Check dependencies
	for inputName, dep := range opcode.Dependencies {
		if dep.Src == OPCODE {
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
			inputHash, ok := data.InputHashes[inputName]
			if !ok {
				return xerrors.Errorf("cannot find the input data for %s", inputName)
			}
			if !bytes.Equal(inputHash, receipt.HashBytes) {
				return xerrors.Errorf("hashes do not match for input %s", inputName)
			}
			hash := receipt.Hash()
			dfuid := r.EP.Txn.Opcodes[dep.Idx].DFUID
			dfuData, ok := r.EP.DFUData[dfuid]
			if !ok {
				return xerrors.Errorf("cannot find dfu info for %s", dfuid)
			}
			err := receipt.Sig.VerifyWithPolicy(suite, hash, dfuData.Keys,
				sign.NewThresholdPolicy(dfuData.Threshold))
			if err != nil {
				return xerrors.Errorf("cannot verify signature from %s for on opcode receipt: %v", err)
			}
		} else if dep.Src == KEYVALUE {
			proof, ok := data.StateProofs[inputName]
			if !ok {
				return xerrors.Errorf("missing keyvalue for input %s", inputName)
			}
			if !bytes.Equal(r.EP.StateRoot, proof.Proof.InclusionProof.GetRoot()) {
				return xerrors.Errorf("merkle roots do not match")
			}
			publics := r.EP.DFUData[SUID].Keys
			err := proof.VerifyFromBlock(publics)
			if err != nil {
				return xerrors.Errorf("cannot verify keyvalue proof: %v", err)
			}
		} else if dep.Src == PRECOMMIT {
			keys := strings.Split(dep.Value, ",")
			if len(keys) != len(data.Precommits.Data) {
				return xerrors.Errorf("precommit count mismatch: "+
					"expected %d received %d", len(keys), len(data.Precommits.Data))
			}
			for _, key := range keys {
				if _, ok := data.Precommits.Data[key]; !ok {
					return xerrors.Errorf("missing precommit key: %s", key)
				}
			}
		} else if dep.Src == CONST {
			inputHash, ok := data.InputHashes[inputName]
			if !ok {
				return xerrors.Errorf("cannot find the input data for %s", inputName)
			}
			if !bytes.Equal(getHash(dep.Value), inputHash) {
				return xerrors.New("received input does not match the CONST value")
			}
		}
	}
	return nil
}

func getHash(val string) []byte {
	h := sha256.New()
	h.Write([]byte(val))
	return h.Sum(nil)
}

func PrepareKVDicts(r *ExecutionRequest, proofs map[string]*StateProof) (map[string]KVDict, error) {
	idx := r.Index
	opcode := r.EP.Txn.Opcodes[idx]
	kvDicts := make(map[string]KVDict)
	for inputName, dep := range opcode.Dependencies {
		if dep.Src == KEYVALUE {
			v, _, _, err := proofs[inputName].Proof.Get(r.EP.CID)
			if err != nil {
				return nil, err
			}
			storageMap, err := getStorageMap(v)
			if err != nil {
				return nil, err
			}
			keys := strings.Split(dep.Value, ",")
			data := make(map[string][]byte)
			for _, key := range keys {
				val, ok := storageMap[key]
				if !ok {
					return nil, xerrors.Errorf("missing key: %s", key)
				}
				data[key] = val
			}
			kvDicts[inputName] = KVDict{Data: data}
		}
	}
	return kvDicts, nil
}

func getStorageMap(v []byte) (map[string][]byte, error) {
	kvStore := &contracts.Storage{}
	err := protobuf.Decode(v, kvStore)
	if err != nil {
		return nil, err
	}
	smap := make(map[string][]byte)
	for _, kv := range kvStore.Store {
		smap[kv.Key] = kv.Value
	}
	return smap, nil
}

// VerifyFromBlock takes a skipchain id and the first block of the proof. It
// verifies that the proof is valid for this skipchain. It verifies the proof,
// that the merkle-root is stored in the skipblock of the proof and the fact that
// the skipblock is indeed part of the skipchain. It also uses the provided block
// to insure the first roster is correct. If all verifications are correct, the error
// will be nil. It does not verify wether a certain key/value pair exists in the proof.
//func (p StateProof) VerifyFromBlock(verifiedBlock *skipchain.SkipBlock, publics []kyber.Point) error {
func (p StateProof) VerifyFromBlock(publics []kyber.Point) error {
	if len(p.Proof.Links) > 0 {
		// Hash of the block has been verified previously so we can trust the roster
		// coming from it which should be the same. If not, the proof won't verified.
		p.Proof.Links[0].NewRoster = p.Genesis.Roster
	}

	// The signature of the first link is not checked as we use it as
	// a synthetic link to provide the initial roster.
	err := p.verify(p.Genesis.Hash, publics)
	return cothority.ErrorOrNil(err, "verification failed")
}

// Verify takes a skipchain id and verifies that the proof is valid for this
// skipchain. It verifies the proof, that the merkle-root is stored in the
// skipblock of the proof and the fact that the skipblock is indeed part of the
// skipchain. If all verifications are correct, the error will be nil. It does
// not verify whether a certain key/value pair exists in the proof.
func (p StateProof) verify(sbID skipchain.SkipBlockID, publics []kyber.Point) error {
	err := p.Proof.VerifyInclusionProof(&p.Proof.Latest)
	if err != nil {
		return cothority.WrapError(err)
	}

	if len(p.Proof.Links) == 0 {
		return cothority.WrapError(byzcoin.ErrorMissingForwardLinks)
	}
	if p.Proof.Links[0].NewRoster == nil {
		return cothority.WrapError(byzcoin.ErrorMalformedForwardLink)
	}

	// Get the first from the synthetic link which is assumed to be verified
	// before against the block with ID stored in the To field by the caller.
	//publics := p.Proof.Links[0].NewRoster.ServicePublics(skipchain.ServiceName)

	for _, l := range p.Proof.Links[1:] {
		if err = l.VerifyWithScheme(pairing.NewSuiteBn256(), publics, p.Proof.Latest.SignatureScheme); err != nil {
			return cothority.WrapError(byzcoin.ErrorVerifySkipchain)
		}
		if !l.From.Equal(sbID) {
			return cothority.WrapError(byzcoin.ErrorVerifySkipchain)
		}
		sbID = l.To
		//if l.NewRoster != nil {
		//	publics = l.NewRoster.ServicePublics(skipchain.ServiceName)
		//}
	}

	// Check that the given latest block matches the last forward link target
	if !p.Proof.Latest.CalculateHash().Equal(sbID) {
		return cothority.WrapError(byzcoin.ErrorVerifyHash)
	}

	return nil
}

func (p *ExecutionPlan) Hash() []byte {
	h := sha256.New()
	// CID
	h.Write(p.CID)
	// StateRoot
	h.Write(p.StateRoot)
	// CodeHash
	h.Write(p.CodeHash)
	//WfName
	h.Write([]byte(p.WfName))
	// TxnName
	h.Write([]byte(p.TxnName))

	// Serialize transaction
	for _, opcode := range p.Txn.Opcodes {
		h.Write([]byte(opcode.Name))
		h.Write([]byte(opcode.DFUID))

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
			h.Write([]byte(k))
			h.Write([]byte(dep.Src))
			h.Write([]byte(dep.SrcName))
			h.Write(b)
			//h.Write([]byte(dep.Value))
			h.Write(getValueBytes(dep.Value))
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
		h.Write([]byte(k))
		binary.LittleEndian.PutUint64(b, uint64(p.DFUData[k].Threshold))
		h.Write(b)
		for _, pk := range p.DFUData[k].Keys {
			h.Write([]byte(pk.String()))
		}
	}
	return h.Sum(nil)
}

func getValueBytes(i interface{}) []byte {
	switch v := i.(type) {
	case int:
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, uint64(v))
		return b
	case string:
		return []byte(v)
	}
	return nil
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
	h.Write(r.EPID)
	// OpIdx
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, uint64(r.OpIdx))
	h.Write(b)
	// Name
	h.Write([]byte(r.Name))
	// HashBytes
	h.Write(r.HashBytes)
	return h.Sum(nil)
}
