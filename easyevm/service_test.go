package easyevm

import (
	"encoding/hex"
	"io/ioutil"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.dedis.ch/kyber/v3/suites"
	"go.dedis.ch/onet/v3"
)

var tSuite = suites.MustFind("Ed25519")

var txParams = struct {
	// maximum amount of Gas that a user is willing to pay for performing an
	// action or confirming a transaction
	GasLimit uint64

	// amount of Gwei (nano ether) that the user is willing to spend on each
	// unit of Gas
	GasPrice *big.Int
}{1e7, big.NewInt(1)}

// borrowed from cothority/bevm
var testPrivateKeys = []string{
	"c87509a1c067bbde78beb793e6fa76530b6382a4c0241e5e4a9ec0a0f44dc0d3",
	"ae6ae8e5ccbfb04590405997ee2d52d2b330726137b875053c36d94e974d162f",
	"8503d4206b83002eee8ffe8a11c2b09885a0912f5cddd2401d96c3abccca7401",
	"f78572bd69fbd3118ab756e3544d23821a2002b137c9037a3b8fd5b09169a73c",
}

// This scenario uses the candy contract. It does the following:
// 1. Spwan a candy contract with 100 candies
// 2. Check the db to see if the new instance has 100 candies
// 3. Call the "eatCandies" function on the instance to eat 10 candies
// 4. Check that the instance has 90 candies left
func TestService_ExecEVM_Candy(t *testing.T) {
	local := onet.NewTCPTest(tSuite)

	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, easyevmID)

	require.Len(t, services, 5)
	require.IsType(t, &Service{}, services[0])

	service := services[0].(*Service)

	//
	// 0: Setup steps. We create a new account, set up a new database, add some
	// balance to the account, and load the solidity candy contract.
	//

	account, err := NewEvmAccount(testPrivateKeys[0])
	require.NoError(t, err)

	raw := rawdb.NewMemoryDatabase()

	db := state.NewDatabase(raw)
	stateDb, err := state.New(*root, db, nil)
	require.NoError(t, err)

	// 1e7 is not sufficient to run two time the candy smart contract
	stateDb.AddBalance(account.Address, big.NewInt(1e8))

	root, err := stateDb.Commit(true)
	require.NoError(t, err)

	err = stateDb.Database().TrieDB().Commit(root, true)
	require.NoError(t, err)

	mapdb := make(map[string][]byte)

	rawIter := raw.NewIterator(nil, nil)
	for rawIter.Next() {
		mapdb[string(rawIter.Key())] = rawIter.Value()
	}
	rawIter.Release()

	// This contract costs around 200k gas
	candyBuf, err := ioutil.ReadFile("testdata/Candy/Candy_sol_Candy.bin")
	require.NoError(t, err)

	contractBytecode, err := hex.DecodeString(string(candyBuf))
	require.NoError(t, err)

	candyJSON, err := ioutil.ReadFile("testdata/Candy/Candy_sol_Candy.abi")
	require.NoError(t, err)

	contractAbi, err := abi.JSON(strings.NewReader(string(candyJSON)))
	require.NoError(t, err)

	//
	// 1: Call a Spawn with 100 initial candies
	//

	candySupply := big.NewInt(100)
	packedArgs, err := contractAbi.Pack("", candySupply)
	require.NoError(t, err)

	callData := append(contractBytecode, packedArgs...)

	tx := types.NewContractCreation(uint64(0), big.NewInt(int64(0)),
		txParams.GasLimit, txParams.GasPrice, callData)

	var signer types.Signer = types.HomesteadSigner{}
	tx, err = types.SignTx(tx, signer, account.PrivateKey)
	require.NoError(t, err)

	txJSON, err := tx.MarshalJSON()
	require.NoError(t, err)

	execRequest := &ExecEVM{
		Roster: roster,
		db:     mapdb,
		txJSON: txJSON,
		root:   &root,
	}

	reply, err := service.ExecEVM(execRequest)
	require.NoError(t, err)

	var receipt types.Receipt
	err = receipt.UnmarshalJSON(reply.receiptJSON)
	require.NoError(t, err)

	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	// this is the address of our new instance
	instanceAddr := crypto.CreateAddress(account.Address, 0)

	//
	// 2: Get the current amount of candies, should be 100
	//

	raw = rawdb.NewMemoryDatabase()

	for k, v := range reply.db {
		raw.Put([]byte(k), v)
	}

	db = state.NewDatabase(raw)
	stateDb, err = state.New(*reply.root, db, nil)
	require.NoError(t, err)

	res, err := CallEVM(stateDb, account.Address, instanceAddr, contractAbi,
		"getRemainingCandies")
	require.Nil(t, err)

	require.Len(t, res, 1)
	require.Equal(t, big.NewInt(100), res[0])

	//
	// 3: Call an invoke on the instance to eat 10 candies
	//

	candyEat := big.NewInt(10)
	packedArgs, err = contractAbi.Pack("eatCandy", candyEat)
	require.NoError(t, err)

	callData = packedArgs

	tx = types.NewTransaction(uint64(1), instanceAddr, big.NewInt(int64(0)),
		txParams.GasLimit, txParams.GasPrice, callData)

	tx, err = types.SignTx(tx, signer, account.PrivateKey)
	require.NoError(t, err)

	txJSON, err = tx.MarshalJSON()
	require.NoError(t, err)

	execRequest = &ExecEVM{
		Roster: roster,
		db:     reply.db,
		txJSON: txJSON,
		root:   reply.root,
	}

	reply, err = service.ExecEVM(execRequest)
	require.NoError(t, err)

	err = receipt.UnmarshalJSON(reply.receiptJSON)
	require.NoError(t, err)

	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	//
	// 4: Get the current amount of candies, should be 90
	//

	raw = rawdb.NewMemoryDatabase()

	for k, v := range reply.db {
		raw.Put([]byte(k), v)
	}

	db = state.NewDatabase(raw)
	stateDb, err = state.New(*reply.root, db, nil)
	require.NoError(t, err)

	res, err = CallEVM(stateDb, account.Address, instanceAddr, contractAbi,
		"getRemainingCandies")
	require.Nil(t, err)

	require.Len(t, res, 1)
	require.Equal(t, big.NewInt(90), res[0])
}

// This scenario uses the ERC20 contract. It does the following:
// 1. Create a new ERC instance
// 2. Check the total supply of the ERC instance and initial balance of accountA
// 3. Check the initial balance of accountB
// 4. Transfer 100 tokens from accountA to accountB
// 5. Check the new balances of both accounts
// 6. Try to transfer 101 tokens from accountB to accountA, which should fail
// 7. Check that the balances are still right
func TestService_ExecEVM_ERC20(t *testing.T) {
	local := onet.NewTCPTest(tSuite)

	hosts, roster, _ := local.GenTree(5, true)
	defer local.CloseAll()

	services := local.GetServices(hosts, easyevmID)

	require.Len(t, services, 5)
	require.IsType(t, &Service{}, services[0])

	service := services[0].(*Service)

	//
	// 0: Setup steps. We create two new accounts, set up a new database, add
	// some balance to accountA, and load the solidity candy contract.
	//

	accountA, err := NewEvmAccount(testPrivateKeys[0])
	require.NoError(t, err)

	accountB, err := NewEvmAccount(testPrivateKeys[1])
	require.NoError(t, err)

	raw := rawdb.NewMemoryDatabase()

	db := state.NewDatabase(raw)
	stateDb, err := state.New(*root, db, nil)
	require.NoError(t, err)

	// credit account 1
	stateDb.AddBalance(accountA.Address, big.NewInt(5*WeiPerEther))

	// credit account 2
	stateDb.AddBalance(accountB.Address, big.NewInt(5*WeiPerEther))

	root, err := stateDb.Commit(true)
	require.NoError(t, err)

	err = stateDb.Database().TrieDB().Commit(root, true)
	require.NoError(t, err)

	mapdb := make(map[string][]byte)

	rawIter := raw.NewIterator(nil, nil)
	for rawIter.Next() {
		mapdb[string(rawIter.Key())] = rawIter.Value()
	}
	rawIter.Release()

	contractBuf, err := ioutil.ReadFile("testdata/ERC20Token/ERC20Token_sol_ERC20Token.bin")
	require.NoError(t, err)

	contractBytecode, err := hex.DecodeString(string(contractBuf))
	require.NoError(t, err)

	contractJSON, err := ioutil.ReadFile("testdata/ERC20Token/ERC20Token_sol_ERC20Token.abi")
	require.NoError(t, err)

	contractAbi, err := abi.JSON(strings.NewReader(string(contractJSON)))
	require.NoError(t, err)

	//
	// 1: Spawn an ERC contract with accountA as the owner
	//

	packedArgs, err := contractAbi.Pack("")
	require.NoError(t, err)

	callData := append(contractBytecode, packedArgs...)

	tx := types.NewContractCreation(accountA.GetAndIncrement(),
		big.NewInt(int64(0)), txParams.GasLimit, txParams.GasPrice, callData)

	var signer types.Signer = types.HomesteadSigner{}
	tx, err = types.SignTx(tx, signer, accountA.PrivateKey)
	require.NoError(t, err)

	txJSON, err := tx.MarshalJSON()
	require.NoError(t, err)

	execRequest := &ExecEVM{
		Roster: roster,
		db:     mapdb,
		txJSON: txJSON,
		root:   &root,
	}

	reply, err := service.ExecEVM(execRequest)
	require.NoError(t, err)

	var receipt types.Receipt
	err = receipt.UnmarshalJSON(reply.receiptJSON)
	require.NoError(t, err)

	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	// this is the address of our new ERC instance. Nonce-1 is the value of the
	// Nonce that we used to spawn the instance, since we did a getAndIncrement.
	instanceAddr := crypto.CreateAddress(accountA.Address, accountA.Nonce-1)

	//
	// 2: Get the total supply for accountA and its initial balance. The two
	// should be equal, as accountA is the owner of the ERC account instance
	//

	raw = rawdb.NewMemoryDatabase()

	for k, v := range reply.db {
		raw.Put([]byte(k), v)
	}

	db = state.NewDatabase(raw)
	stateDb, err = state.New(*reply.root, db, nil)
	require.NoError(t, err)

	// Get the total supply
	res, err := CallEVM(stateDb, accountA.Address, instanceAddr, contractAbi,
		"totalSupply")
	require.NoError(t, err)

	require.Len(t, res, 1)
	supply := res[0]

	// Get the initial balance
	res, err = CallEVM(stateDb, accountA.Address, instanceAddr, contractAbi,
		"balanceOf", accountA.Address)
	require.NoError(t, err)

	require.Len(t, res, 1)
	require.Equal(t, supply, res[0])

	//
	// 3: Check balance of accountB, which should be empty
	//

	res, err = CallEVM(stateDb, accountA.Address, instanceAddr, contractAbi,
		"balanceOf", accountB.Address)
	require.NoError(t, err)

	require.Len(t, res, 1)
	require.IsType(t, big.NewInt(0), res[0])
	require.Zero(t, big.NewInt(0).Cmp(res[0].(*big.Int)))

	//
	// 4: Transfert 100 tokens from accountA to accountB
	//

	transferAmount := big.NewInt(100)
	transferTo := accountB.Address

	packedArgs, err = contractAbi.Pack("transfer", transferTo, transferAmount)
	require.NoError(t, err)

	callData = packedArgs

	tx = types.NewTransaction(accountA.GetAndIncrement(), instanceAddr,
		big.NewInt(int64(0)), txParams.GasLimit, txParams.GasPrice, callData)

	tx, err = types.SignTx(tx, signer, accountA.PrivateKey)
	require.NoError(t, err)

	txJSON, err = tx.MarshalJSON()
	require.NoError(t, err)

	execRequest = &ExecEVM{
		Roster: roster,
		db:     reply.db,
		txJSON: txJSON,
		root:   reply.root,
	}

	reply, err = service.ExecEVM(execRequest)
	require.NoError(t, err)

	err = receipt.UnmarshalJSON(reply.receiptJSON)
	require.NoError(t, err)

	require.Equal(t, types.ReceiptStatusSuccessful, receipt.Status)

	//
	// 5: Check the new balances of accountA and accountB
	//

	new1 := new(big.Int).Sub(supply.(*big.Int), big.NewInt(100))
	new2 := big.NewInt(100)

	raw = rawdb.NewMemoryDatabase()

	for k, v := range reply.db {
		raw.Put([]byte(k), v)
	}

	db = state.NewDatabase(raw)
	stateDb, err = state.New(*reply.root, db, nil)
	require.NoError(t, err)

	res, err = CallEVM(stateDb, accountA.Address, instanceAddr, contractAbi,
		"balanceOf", accountA.Address)
	require.NoError(t, err)

	require.Len(t, res, 1)
	require.Equal(t, new1, res[0])

	res, err = CallEVM(stateDb, accountA.Address, instanceAddr, contractAbi,
		"balanceOf", accountB.Address)
	require.NoError(t, err)

	require.Len(t, res, 1)
	require.Equal(t, new2, res[0])

	//
	// 6: Try to transfer 101 tokens from accountB to accountA. It should be
	// rejected.
	//

	transferAmount = big.NewInt(101)
	transferTo = accountA.Address

	packedArgs, err = contractAbi.Pack("transfer", transferTo, transferAmount)
	require.NoError(t, err)

	callData = packedArgs

	tx = types.NewTransaction(accountB.GetAndIncrement(), instanceAddr,
		big.NewInt(int64(0)), txParams.GasLimit, txParams.GasPrice, callData)

	tx, err = types.SignTx(tx, signer, accountB.PrivateKey)
	require.NoError(t, err)

	txJSON, err = tx.MarshalJSON()
	require.NoError(t, err)

	execRequest = &ExecEVM{
		Roster: roster,
		db:     reply.db,
		txJSON: txJSON,
		root:   reply.root,
	}

	reply, err = service.ExecEVM(execRequest)
	require.NoError(t, err)

	err = receipt.UnmarshalJSON(reply.receiptJSON)
	require.NoError(t, err)

	require.Equal(t, types.ReceiptStatusFailed, receipt.Status)

	//
	// 7: Check that the balances have not changed
	//

	raw = rawdb.NewMemoryDatabase()

	for k, v := range reply.db {
		raw.Put([]byte(k), v)
	}

	db = state.NewDatabase(raw)
	stateDb, err = state.New(*reply.root, db, nil)
	require.NoError(t, err)

	res, err = CallEVM(stateDb, accountA.Address, instanceAddr, contractAbi,
		"balanceOf", accountA.Address)
	require.NoError(t, err)

	require.Len(t, res, 1)
	require.Equal(t, new1, res[0])

	res, err = CallEVM(stateDb, accountA.Address, instanceAddr, contractAbi,
		"balanceOf", accountB.Address)
	require.NoError(t, err)

	require.Len(t, res, 1)
	require.Equal(t, new2, res[0])
}
