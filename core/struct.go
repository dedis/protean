package core

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/kyber/v3"
)

// Workflow

const (
	CONST    string = "CONST"
	KEYVALUE string = "KEYVALUE"
	OPCODE   string = "OPCODE"
)

type Contract struct {
	Workflows map[string]*Workflow `json:"workflows"`
	DFUs      []string             `json:"dfus"`
}

type Workflow struct {
	Txns       map[string]*Transaction `json:"txns"`
	Precommits []string                `json:"precommits"`
}

type Transaction struct {
	Opcodes []*Opcode `json:"opcodes"`
}

type Opcode struct {
	Name         string                     `json:"name"`
	DFUID        string                     `json:"dfu_id"`
	Dependencies map[string]*DataDependency `json:"inputs,omitempty"`
}

type DataDependency struct {
	Src     string `json:"src"`
	SrcName string `json:"src_name,omitempty"`
	Idx     int    `json:"idx,omitempty"`
	Value   string `json:"value,omitempty"`
}

// Execution data

type ExecutionPlan struct {
	CID       []byte
	StateRoot []byte
	CodeHash  []byte
	WfName    string
	TxnName   string
	Txn       *Transaction
	DFUData   map[string]*DFUIdentity
}

type ExecutionRequest struct {
	Index      int
	EP         *ExecutionPlan
	EPSig      protocol.BlsSignature // from CEU
	OpReceipts map[string]*OpcodeReceipt
	//OpReceiptSigs map[string]protocol.BlsSignature
	KVReceipt    map[string]KVDict
	KVReceiptSig protocol.BlsSignature
}

type OpcodeReceipt struct {
	EPID  string // Hash of the execution plan
	OpIdx int
	//OpName string
	// Name of the output variable
	Name string
	// digest = H(output)
	Digest []byte
	Sig    protocol.BlsSignature
}

type DFUIdentity struct {
	Threshold int
	Keys      []kyber.Point
}

// FSM

type FSM struct {
	InitialState string                 `json:"initial_state"`
	States       []string               `json:"states"`
	Transitions  map[string]*Transition `json:"transitions"`
}

type Transition struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// DFU

type DFURegistry struct {
	Units map[string]*DFU `json:"registry"`
}

type DFU struct {
	NumNodes  int           `json:"num_nodes"`
	Threshold int           `json:"threshold"`
	Opcodes   []string      `json:"opcodes"`
	Keys      []kyber.Point `json:",omitempty"`
}

// State

type ContractHeader struct {
	CID       byzcoin.InstanceID
	Contract  *Contract
	FSM       *FSM
	CodeHash  []byte
	Lock      []byte
	CurrState string
}

// This is the value that is stored with key "kvstore". Keyvalue contract stores
// key-value pairs in a list instead of a Go map since the latter is
// non-deterministic. This can result in poor lookup performance. To work around
// this problem, we store the key-value pairs in a KVDict and store the
// protobuf-encoded struct in the contract.

type KVDict struct {
	Data map[string][]byte
}

type StateProof struct {
	Proof byzcoin.Proof
}

type ReadState struct {
	Root []byte
	KV   KVDict
	Sig  protocol.BlsSignature
}
