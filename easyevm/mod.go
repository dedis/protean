package easyevm

import (
	"crypto/ecdsa"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"golang.org/x/xerrors"
)

// WeiPerEther represents the number of Wei (the smallest currency denomination
// in Ethereum) in a single Ether.
const WeiPerEther = 1e18

var nilAddress = common.HexToAddress(
	"0x0000000000000000000000000000000000000000")

// EvmAccount is the abstraction for an Ethereum account
type EvmAccount struct {
	Address    common.Address
	PrivateKey *ecdsa.PrivateKey
	Nonce      uint64
}

// NewEvmAccount creates a new EvmAccount
func NewEvmAccount(privateKey string) (*EvmAccount, error) {
	privKey, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return nil, xerrors.Errorf("failed to decode private "+
			"key for account creation: %v", err)
	}

	address := crypto.PubkeyToAddress(privKey.PublicKey)

	return &EvmAccount{
		Address:    address,
		PrivateKey: privKey,
	}, nil
}

// GetAndIncrement returns the current nonce value and then increments it.
func (e *EvmAccount) GetAndIncrement() uint64 {
	res := e.Nonce
	e.Nonce++
	return res
}

// CallEVM allows one to call a "getter" function on a smart contract, ie. a
// function that does not modify the state of the db but just return some info.
func CallEVM(stateDb *state.StateDB, accountAddr, instanceAddr common.Address,
	contractAbi abi.ABI, method string, args ...interface{}) ([]interface{}, error) {

	callData, err := contractAbi.Pack(method, args...)
	if err != nil {
		return nil, xerrors.Errorf("failed to pack method: %v", err)
	}

	timestamp := time.Now().UnixNano()

	// Instantiate a new EVM
	evm := vm.NewEVM(getContext(timestamp), stateDb, getChainConfig(),
		getVMConfig())

	// Perform the call (1 Ether should be enough for everyone [tm]...)
	ret, _, err := evm.Call(vm.AccountRef(accountAddr),
		instanceAddr, callData, uint64(1*WeiPerEther),
		big.NewInt(0))
	if err != nil {
		return nil, xerrors.Errorf("failed to execute EVM view "+
			"method: %v", err)
	}

	// Unpack the returned value(s)
	methodAbi, ok := contractAbi.Methods[method]
	if !ok {
		return nil, xerrors.Errorf("method \"%s\" does not exist for "+
			"this contract", method)
	}

	itfs, err := methodAbi.Outputs.UnpackValues(ret)
	if err != nil {
		return nil, xerrors.Errorf("failed to unpack values: %v", err)
	}

	return itfs, nil
}

// getContext is a utility function to get the ethereum vm context
func getContext(timestamp int64) vm.Context {
	placeHolder := common.HexToAddress("0")

	return vm.Context{
		CanTransfer: func(vm.StateDB, common.Address, *big.Int) bool {
			return true
		},
		Transfer: func(vm.StateDB, common.Address, common.Address, *big.Int) {
		},
		GetHash: func(uint64) common.Hash {
			return common.HexToHash("0")
		},
		Origin:      placeHolder,
		GasPrice:    big.NewInt(0),
		Coinbase:    placeHolder,
		GasLimit:    10000000000,
		BlockNumber: big.NewInt(0),
		Time:        big.NewInt(timestamp),
		Difficulty:  big.NewInt(1),
	}
}

func getChainConfig() *params.ChainConfig {
	// ChainConfig (adapted from Rinkeby test net)
	chainconfig := &params.ChainConfig{
		ChainID:        big.NewInt(1),
		HomesteadBlock: big.NewInt(0),
		DAOForkBlock:   nil,
		DAOForkSupport: false,
		EIP150Block:    nil,
		EIP150Hash: common.HexToHash(
			"0x0000000000000000000000000000000000000000"),
		EIP155Block:    big.NewInt(0),
		EIP158Block:    big.NewInt(0),
		ByzantiumBlock: big.NewInt(0),
		// Enable new Constantinople instructions
		ConstantinopleBlock: big.NewInt(0),
		Clique: &params.CliqueConfig{
			Period: 15,
			Epoch:  30000,
		},
	}

	return chainconfig
}

func getVMConfig() vm.Config {
	// vmConfig Config
	vmconfig := &vm.Config{
		// Debug enables debugging Interpreter options
		Debug: false,
		// Tracer is the op code logger
		Tracer: nil,
		// NoRecursion disables Interpreter call, callcode,
		// delegate call and create.
		NoRecursion: false,
		// Enable recording of SHA3/keccak preimages
		EnablePreimageRecording: true,
		// JumpTable contains the EVM instruction table. This
		// may be left uninitialised and will be set to the default
		// table.
		//JumpTable [256]operation
		//JumpTable: ,
		// Type of the EWASM interpreter
		EWASMInterpreter: "",
		// Type of the EVM interpreter
		EVMInterpreter: "",
	}

	return *vmconfig
}
