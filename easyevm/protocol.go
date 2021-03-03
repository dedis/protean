package easyevm

import (
	"bytes"
	"math/big"
	"sort"

	"crypto/sha256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"golang.org/x/xerrors"
)

// ProtocolName is the name of the EasyEVM protocol
const ProtocolName = "EasyEVMProtocol"

var root = new(common.Hash)

func init() {
	_, err := onet.GlobalProtocolRegister(ProtocolName, NewProtocol)
	log.ErrFatal(err)
}

// easyevmProtocol represents an Onet protocol intance
//
// - implements onet.ProtocolInstance
type easyevmProtocol struct {
	*onet.TreeNodeInstance
	announceChan chan announceWrapper
	repliesChan  chan []replyWrapper
	ResultChan   chan *Reply

	txJSON    []byte
	db        map[string][]byte
	timestamp int
	root      *common.Hash
}

// Announce is the message sent that starts the protocol. In our case this
// message decribes the exectution of a solidity smart contract on a given
// Ethereum database.
type Announce struct {
	TxJSON    []byte
	DB        map[string][]byte
	Timestamp int
	Root      *common.Hash
}

// announceWrapper is the Onet wrapper for a Reply
type announceWrapper struct {
	*onet.TreeNode
	Announce
}

// Reply is the result of our protocol and the result of each individual
// children. In our case the result of executing a solidity smart contract on a
// given Ethereume database.
type Reply struct {
	DB          map[string][]byte
	ReceiptJSON []byte
	Root        *common.Hash
}

// Hash returns the hash of a Reply.
func (r Reply) Hash() []byte {
	h := sha256.New()

	h.Write(r.ReceiptJSON)
	h.Write(r.Root.Bytes())

	// we get all the keys and sort them to have a deterministic behavior
	keys := make([]string, 0, len(r.DB))
	for k := range r.DB {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		h.Write([]byte(k))
		h.Write(r.DB[k])
	}

	return h.Sum(nil)
}

// replyWrapper is the Onet wrapper for a Reply
type replyWrapper struct {
	*onet.TreeNode
	Reply
}

// NewProtocol initilializes and registers the protocol.
func NewProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	e := &easyevmProtocol{
		TreeNodeInstance: n,
		ResultChan:       make(chan *Reply),
	}

	err := n.RegisterChannels(&e.announceChan, &e.repliesChan)
	log.ErrFatal(err)

	return e, nil
}

// Start implements onet.ProtocolInstance. It sends the Announce message to all
// children.
func (e *easyevmProtocol) Start() error {
	return e.SendTo(e.TreeNode(), &Announce{
		TxJSON:    e.txJSON,
		DB:        e.db,
		Timestamp: e.timestamp,
		Root:      e.root,
	})
}

// Dispatch implements onet.ProtocolInstance. It describes the logic of the
// protocol. This function is only called once. The protocol is considered
// finished when Dispatch returns and Done is called.
func (e *easyevmProtocol) Dispatch() error {
	defer e.Done()

	ann := <-e.announceChan
	if e.IsLeaf() {
		// the actual part that executes the smart contract
		receipt, db, root, err := sendTx(ann.Announce)
		if err != nil {
			return xerrors.Errorf("failed to send Tx: %v", err)
		}

		// The other side won't be able to call unmarshalJSON if this field is
		// nil. Is it a bug? Maybe.
		if receipt.Logs == nil {
			receipt.Logs = make([]*types.Log, 0)
		}

		receiptBuf, err := receipt.MarshalJSON()
		if err != nil {
			return xerrors.Errorf("failed to marshal receipt: %v", err)
		}

		return e.SendToParent(&Reply{
			DB:          db,
			ReceiptJSON: receiptBuf,
			Root:        root,
		})
	}

	err := e.SendToChildren(&ann.Announce)
	if err != nil {
		return xerrors.Errorf("failed to send to children: %v", err)
	}

	replies := <-e.repliesChan

	if len(replies) == 0 {
		return xerrors.Errorf("expected at least one reply")
	}

	// We check that each node return the exact same reply, ie. that the hash of
	// each reply are the same.
	hash := replies[0].Hash()
	for _, reply := range replies[1:] {
		hash2 := reply.Hash()
		if !bytes.Equal(hash, hash2) {
			return xerrors.Errorf("missmatch between two replies: %x - %x",
				hash, hash2)
		}

		hash = hash2
	}

	if !e.IsRoot() {
		return e.SendToParent(&replies[0].Reply)
	}

	e.ResultChan <- &replies[0].Reply

	return nil
}

// sendTx sends a transaction to the Ethereum virtual machine and returns the
// updated database.
func sendTx(ann Announce) (*types.Receipt, map[string][]byte, *common.Hash, error) {

	// Gets the needed parameters
	chainConfig := getChainConfig()
	vmConfig := getVMConfig()

	// GasPool tracks the amount of gas available during execution of the
	// transactions in a block
	gp := new(core.GasPool).AddGas(uint64(1e18))
	usedGas := uint64(0)
	ug := &usedGas

	// ChainContext supports retrieving headers and consensus parameters from
	// the current blockchain to be used during transaction processing.
	var bc core.ChainContext

	// Header represents a block header in the Ethereum blockchain.
	header := &types.Header{
		Number:     big.NewInt(0),
		Difficulty: big.NewInt(0),
		ParentHash: common.Hash{0},
		Time:       uint64(ann.Timestamp),
	}

	var ethTx types.Transaction
	err := ethTx.UnmarshalJSON(ann.TxJSON)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("failed to unmarshal tx: %v", err)
	}

	rawdb := rawdb.NewMemoryDatabase()

	for k, v := range ann.DB {
		rawdb.Put([]byte(k), v)
	}

	db := state.NewDatabase(rawdb)
	stateDb, err := state.New(*ann.Root, db, nil)

	// Apply transaction to the general EVM state
	receipt, err := core.ApplyTransaction(chainConfig, bc,
		&nilAddress, gp, stateDb, header, &ethTx, ug, vmConfig)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("failed to apply transaction "+
			"on EVM: %v", err)
	}

	root, err := stateDb.Commit(true)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("failed to commit stateDB: %v", err)
	}

	err = stateDb.Database().TrieDB().Commit(root, true)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("failed to commit Trie: %v", err)
	}

	newdb := make(map[string][]byte, 0)

	rawIter := rawdb.NewIterator(nil, nil)
	for rawIter.Next() {
		newdb[string(rawIter.Key())] = rawIter.Value()
	}
	rawIter.Release()

	return receipt, newdb, &root, nil
}
