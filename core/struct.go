package core

import (
	"go.dedis.ch/cothority/v3/blscosi/protocol"
	"go.dedis.ch/cothority/v3/byzcoin"
	"go.dedis.ch/cothority/v3/skipchain"
	"go.dedis.ch/kyber/v3"
)

// Workflow

const (
	SUID  string = "state"
	CEUID string = "codeexec"
)

const (
	OPCODE    string = "OPCODE"
	KEYVALUE  string = "KEYVALUE"
	PRECOMMIT string = "PRECOMMIT"
	CONST     string = "CONST"
)

type Contract struct {
	Workflows map[string]*Workflow `json:"workflows"`
	DFUs      []string             `json:"dfus"`
}

type Workflow struct {
	Txns map[string]*Transaction `json:"txns"`
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
	Src     string      `json:"src"`
	SrcName string      `json:"src_name,omitempty"`
	Idx     int         `json:"idx,omitempty"`
	Value   interface{} `json:"value,omitempty"`
	// This is a terrible hack but the only quick way I could think of to
	//make it work with protobuf.
	//DataDependency is serialized as part of sending the contract
	//data to the state unit. However,
	//protobuf does not like the interface{} type. Therefore,
	//after reading in the JSON files,
	//we check the type of Value; assign its value to one of the following
	//variables; and set Value to nil.
	StringValue string
	UintValue   uint64
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
	Sig       protocol.BlsSignature
}

type ExecutionRequest struct {
	Index      int
	EP         *ExecutionPlan
	OpReceipts map[string]*OpcodeReceipt
}

type OpcodeReceipt struct {
	EPID  []byte // Hash of the execution plan
	OpIdx int
	//OpName string
	// Name of the output variable
	Name string
	// hash = H(output)
	HashBytes []byte
	Sig       protocol.BlsSignature
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

type ContractRaw struct {
	CID      byzcoin.InstanceID
	Contract *Contract
	FSM      *FSM
}

type ContractHeader struct {
	CID       byzcoin.InstanceID
	CodeHash  []byte
	Lock      []byte
	CurrState string
}

type StateProof struct {
	Proof   byzcoin.Proof
	Genesis skipchain.SkipBlock
}

type KVDict struct {
	Data map[string][]byte
}
