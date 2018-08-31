package commands

import (
	// "runtime"
	// "runtime/pprof"
	"flag"
	// "bytes"
	// "encoding/hex"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"os"
	"path"
	"strconv"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	ethMath "github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/spf13/viper"
	"github.com/tendermint/tmlibs/cli"
	// "github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/dora/ultron/app"
)

var (
	rootDir         = "/tmp/.ultron_memdb"          //init folder first
	accountInfoDB   = "simple-test-info.json" // a file to save some test info
	to              = common.HexToAddress("0x0413c6cc6d4381489815b35118f6fa3a1d45a3f9")
	from            = common.HexToAddress("0xcd89dde88bc4e308e436f9f696454840ff795d84")
	defaultAmount   = big.NewInt(1)
	gasprice        = big.NewInt(2.5e9) // should be higher than 2gwei (asked by ethermint)
	gaslimit        = big.NewInt(5e6)
	genesisAccounts = 128
)

type TestService struct {
	t       *testing.T
	chainID string
	srv     *Services
}

var (
	// Define args flags.
	pAccountNum = flag.Int("testAccountNumber", genesisAccounts,  "Generate account number.")
	pTxScale = flag.Int("testTxScale", genesisAccounts * 2, "Scale of txs")
	pRootDir = flag.String("home", rootDir, "Scale of txs")

	// define large scale account num and tx scale
	accountNum = genesisAccounts
	txScale = genesisAccounts
)

func parseFlags() {
	flag.Parse()
	txScale = *pTxScale
	accountNum = *pAccountNum
	rootDir = *pRootDir
}

func SetupTestConfig(homeDir string) bool {
	//ParseConfig()
	viper.Set(cli.HomeFlag, homeDir)
	viper.SetConfigName("config") // name of config file (without extension)
	viper.AddConfigPath(homeDir)  // search root directory
	viper.Set(FlagLogLevel, defaultLogLevel)

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		// stderr, so if we redirect output to json file, this doesn't appear
		// fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	} else if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
		// we ignore not found error, only parse error
		// stderr, so if we redirect output to json file, this doesn't appear
		fmt.Fprintf(os.Stderr, "%#v", err)
	}

	return true
}

func NewTestService() (*Services, error) {
	parseFlags()
	SetupTestConfig(rootDir)
	preRunSetup(nil, nil)

	// cmdName := "test"
	appName := "test"
	storeApp, err := app.NewStoreApp(
		appName,
		path.Join(rootDir, "data", "merkleeyes.db"),
		EyesCacheSize,
		logger.With("module", "app"))
	if err != nil {
		return nil, err
	}

	return startServices(rootDir, storeApp)
}

func transaction(nonce uint64, gaslimit *big.Int, key *ecdsa.PrivateKey, to common.Address, amount *big.Int) *types.Transaction {
	tx := types.NewTransaction(nonce, to, amount, gaslimit, gasprice, nil)
	return tx
}

/**
 * Test Smart Contract Contents:
 *
 *  	pragma solidity ^0.4.16;
 *
 *  	contract CharityBank {
 *  	    address public owner;
 *  	    uint256 public fund;
 *
 *  	    constructor() public {owner = msg.sender; }
 *
 *  	    function close() public { if (msg.sender == owner) selfdestruct(owner); }
 *
 *  	    function deposit() payable public {
 *  	        require(msg.value > 0);
 *  	        fund += msg.value;
 *  	    }
 *
 *  	    function withdraw(uint256 amount) public {
 *  	        require(amount < fund);
 *  	        fund -= amount;
 *  	        address people = msg.sender;
 *  	        people.transfer(amount);
 *  	    }
 *  	}
**/
// compiled code
var compiledContract = "608060405234801561001057600080fd5b50336000806101000a81548173ffff" +
	"ffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffff" +
	"ffffffffffffffffffffffff1602179055506102bb806100606000396000f300" +
	"60806040526004361061006d576000357c010000000000000000000000000000" +
	"0000000000000000000000000000900463ffffffff1680632e1a7d4d14610072" +
	"57806343d726d61461009f5780638da5cb5b146100b6578063b60d4288146101" +
	"0d578063d0e30db014610138575b600080fd5b34801561007e57600080fd5b50" +
	"61009d60048036038101908080359060200190929190505050610142565b005b" +
	"3480156100ab57600080fd5b506100b46101b2565b005b3480156100c2576000" +
	"80fd5b506100cb610243565b604051808273ffffffffffffffffffffffffffff" +
	"ffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260" +
	"200191505060405180910390f35b34801561011957600080fd5b506101226102" +
	"68565b6040518082815260200191505060405180910390f35b61014061026e56" +
	"5b005b60006001548210151561015457600080fd5b8160016000828254039250" +
	"50819055503390508073ffffffffffffffffffffffffffffffffffffffff1661" +
	"08fc839081150290604051600060405180830381858888f19350505050158015" +
	"6101ad573d6000803e3d6000fd5b505050565b6000809054906101000a900473" +
	"ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffff" +
	"ffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffff" +
	"ff161415610241576000809054906101000a900473ffffffffffffffffffffff" +
	"ffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16" +
	"ff5b565b6000809054906101000a900473ffffffffffffffffffffffffffffff" +
	"ffffffffff1681565b60015481565b60003411151561027d57600080fd5b3460" +
	"01600082825401925050819055505600a165627a7a72305820a20d1041740fd7" +
	"e0fb9760f42ce8da0d175635f604134a859ca0ccfb327193580029"

// function hash
var (
	close    = "43d726d6" //: "close()",
	deposit  = "d0e30db0" //: "deposit()",
	found    = "b60d4288" //: "fund()",
	withdraw = "2e1a7d4d" //: "withdraw(uint256)"
)

func newContract(nonce uint64, gaslimit *big.Int, key *ecdsa.PrivateKey, contractStr string) *types.Transaction {
	contractData := common.Hex2Bytes(contractStr)

	contract, _ :=
		types.SignTx(
			types.NewContractCreation(nonce, big.NewInt(0), gaslimit, gasprice, contractData),
			types.HomesteadSigner{},
			key)
	return contract
}

func getTransactionReceipt(txHash common.Hash, eth *eth.Ethereum) (*types.Receipt, error) {
	receipt := core.GetReceipt(eth.ChainDb(), txHash)
	if receipt == nil {
		return nil, fmt.Errorf("Receipt not found for transaction" + txHash.Hex())
	}
	return receipt, nil
}

func getContractAddress(txHash common.Hash, eth *eth.Ethereum) (common.Address, error) {
	receipt, err := getTransactionReceipt(txHash, eth)
	if (err != nil || receipt.ContractAddress == common.Address{}) {
		return common.Address{}, fmt.Errorf("Contract address not found for transaction" + txHash.Hex())
	}
	return receipt.ContractAddress, nil
}

func callContract(nonce uint64, gaslimit *big.Int, key *ecdsa.PrivateKey, contract common.Address, callCode string, amount *big.Int, args []byte) *types.Transaction {
	callData := append(common.Hex2Bytes(callCode), args...)

	contractCallTx, _ :=
		types.SignTx(
			types.NewTransaction(nonce, contract, amount, gaslimit, gasprice, callData),
			types.HomesteadSigner{},
			key)
	return contractCallTx
}

func makeTransaction(s *Services, from *common.Address, passwd string, tx *types.Transaction) *types.Transaction {
	// Look up the wallet containing the requested signer
	am := s.backend.Ethereum().AccountManager()

	account := accounts.Account{Address: *from}

	wallet, _ := am.Find(account)

	chainID := big.NewInt((int64)(config.EMConfig.EthChainId))
	signed, _ := wallet.SignTxWithPassphrase(account, passwd, tx, chainID)
	return signed
}

func wait(hash common.Hash, eth *eth.Ethereum) error {
	repeat := 6
	_, err := getTransactionReceipt(hash, eth)
	for err != nil && repeat > 0 {
		time.Sleep(5 * time.Second)
		_, err = getTransactionReceipt(hash, eth)
		repeat--
	}

	if repeat == 0 {
		return fmt.Errorf("ERROR: wait tx " + hash.Hex() + " timeout!")
	}

	return nil
}

func BenchmarkBasicTxHash(t *testing.B) {
	srv := initSrv
	// defer srv.tmNode.Stop()
	key, _ := crypto.GenerateKey()
	tx := transaction(0, gaslimit, key, to, defaultAmount)
	signedTx := makeTransaction(srv, &from, "dora.io", tx)

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		// time.Sleep(time.Second)
		signedTx.Hash()
	}
}

func newAccount(s *Services, password string) (*TestAccount, error) {
	am := s.backend.Ethereum().AccountManager()
	acc, err := am.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore).NewAccount(password)
	if err == nil {
		return &TestAccount{
			Address:    acc.Address,
			Balance:    big.NewInt(0),
			PassPhrase: password,
			Url:        acc.URL.Path,
		}, nil
	}
	return nil, err
}

var (
	initSrv, _ = NewTestService()
)

func BenchmarkSignBasicTx(t *testing.B) {
	srv := initSrv
	// defer srv.tmNode.Stop()

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		// time.Sleep(time.Second)
		key, _ := crypto.GenerateKey()
		tx := transaction(0, gaslimit, key, to, defaultAmount)
		makeTransaction(srv, &from, "dora.io", tx)
	}
}

func BenchmarkAddBasicTx(t *testing.B) {
	srv := initSrv

	accounts, err := initAccountsForPtxTest(srv, t.N)
	if err != nil {
		t.Fatal(err)
	}

	pool := srv.backend.Ethereum().TxPool()
	state := pool.State()
	queuedTxHash := []common.Hash{}
	txs := types.Transactions{}
	for i := 0; i < t.N; i++ {
		// time.Sleep(time.Second)
		nonce := state.GetNonce(accounts[i].Address)
		key, _ := crypto.GenerateKey()
		tx := transaction(nonce, gaslimit, key, to, defaultAmount)
		signedTx := makeTransaction(srv, &accounts[i].Address, accounts[i].PassPhrase, tx)
		txs = append(txs, signedTx)
		queuedTxHash = append(queuedTxHash, signedTx.Hash())
	}

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		if err := pool.AddRemote(txs[i]); err != nil {
			t.Error("Meet error", err)
		}
	}
	t.StopTimer()

	for _, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			t.Error("Meet error:", err)
		}
	}
}

func BenchmarkNewAccount(t *testing.B) {
	srv := initSrv
	// defer srv.tmNode.Stop()

	t.ResetTimer()
	for i := 0; i < t.N; i++ {
		// seed := time.Now()
		// time.Sleep(time.Second)
		//newAccount(srv, seed.Format("%s"))
		newAccount(srv, "dora.io")
	}
}

func TestGenerateExtendedGenesis(t *testing.T) {
	srv := initSrv
	// defer srv.tmNode.Stop()
	var extendGenesisBlob = []byte(`
	{
		"config": {
			"chainId": 15,
			"homesteadBlock": 0,
			"eip155Block": 0,
			"eip158Block": 0
		},
		"nonce": "0xdeadbeefdeadbeef",
		"timestamp": "0x00",
		"parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
		"mixhash": "0x0000000000000000000000000000000000000000000000000000000000000000",
		"difficulty": "0x40",
		"gasLimit": "0xF00000000",
		"alloc": {
			"0x0413c6cc6d4381489815b35118f6fa3a1d45a3f9": { "balance": "10000000000000000000000000000000000" },
			"0x1780858a3eb6f491adb0b30cc5218746b5f9442c": { "balance": "10000000000000000000000000000000000" },
			"0xfa5787ff486c4093a2f6b6708d28e8e8da6d7957": { "balance": "10000000000000000000000000000000000" },
			"0xc6fc3cfcfd5b8c6ffa8d0b77f8611f001b79717b": { "balance": "10000000000000000000000000000000000" },
			"0xcd89dde88bc4e308e436f9f696454840ff795d84": { "balance": "10000000000000000000000000000000000" }
		}
	}`)

	total := accountNum
	genesis := new(core.Genesis)
	if err := json.Unmarshal(extendGenesisBlob, genesis); err != nil {
		t.Fatal("Meet error: ", err)
	}

	initBalance := genesis.Alloc[common.HexToAddress("0x0413c6cc6d4381489815b35118f6fa3a1d45a3f9")]
	testAccounts := []*TestAccount{}
	for i := 0; i < total; i++ {
		acc, _ := newAccount(srv, "dora.io")
		if _, ok := genesis.Alloc[acc.Address]; !ok {
			genesis.Alloc[acc.Address] = initBalance
			testAccounts = append(testAccounts, acc)
		}
	}

	if len(testAccounts) != total {
		t.Fatal("Generate only ", len(testAccounts), " accounts, not wanted ", total)
	}

	writeJSON(genesis, "extendGenesis.json", 0)
	writeJSON(testAccounts, accountInfoDB, 0)
}

func TestGenerateLargeScaleTxs(t *testing.T) {
	srv := initSrv
	// defer srv.tmNode.Stop()

	accounts, err := initAccountsForPtxTest(srv, accountNum)
	if err != nil {
		t.Fatal(err)
	}
	pool := srv.backend.Ethereum().TxPool()

	queuedTx := types.Transactions{}
	currentState := pool.State()

	loopCnt := txScale * 2 / accountNum
	for nonceOffset := 0; nonceOffset < loopCnt; nonceOffset++ {
		for idx := 0; idx < len(accounts); idx += 2 {
			key, _ := crypto.GenerateKey()
			sender := accounts[idx].Address
			phrase := accounts[idx].PassPhrase
			reciever := accounts[idx+1].Address
			nonce := currentState.GetNonce(sender) + (uint64)(nonceOffset)
			tx := transaction(nonce, gaslimit, key, reciever, defaultAmount)
			signedTx := makeTransaction(srv, &sender, phrase, tx)
			queuedTx = append(queuedTx, signedTx)
		}
	}

	writeJSON(queuedTx, "queued-txs.json", 0)
}

func TestReplayLargeScaleTxs(t *testing.T) {
	srv := initSrv
	pool := srv.backend.Ethereum().TxPool()
	// defer srv.tmNode.Stop()
	queuedTx, ok := loadLargeScaleTxsFile("queued-txs.json")
	if !ok {
		t.Fatal("ERROR: loadLargeScaleTxsFile failed")
	}

	queuedTxHash := []common.Hash{}
	balanceChange := map[*common.Address]int{}
	for _, signedTx := range queuedTx {
		if err := pool.AddRemote(signedTx); err != nil {
			t.Error("Meet error", err)
		}
		queuedTxHash = append(queuedTxHash, signedTx.Hash())
		if _, ok := balanceChange[signedTx.To()]; !ok {
			balanceChange[signedTx.To()] = 1
		} else {
			balanceChange[signedTx.To()] ++
		}
	}

	for index, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			fmt.Println("test meet error index:", index)
			t.Fatal("Meet error:", err)
		}
	}

	newState := pool.State()
	for k, v := range balanceChange {
		t.Log("Meet: final balance of", k.Hex(), " is", newState.GetBalance(*k), ", and target hit is ", v)
	}
}

func TestBasicTx(t *testing.T) {
	srv := initSrv
	defer srv.tmNode.Stop()

	pool := srv.backend.Ethereum().TxPool()
	oldState := pool.State()
	t.Log("Before trans balance: \n", oldState.GetBalance(from), oldState.GetBalance(to))

	nonce := oldState.GetNonce(from)
	queuedTxHash := []common.Hash{}
	queuedTx := types.Transactions{}
	t.Log("start")
	for i := 0; i < 2; i++ {
		key, _ := crypto.GenerateKey()
		tx := transaction(nonce+(uint64)(i), gaslimit, key, to, defaultAmount)
		signedTx := makeTransaction(srv, &from, "dora.io", tx)
		// buf := new(bytes.Buffer)
		// signedTx.EncodeRLP(buf)
		// writeBufferToFile(buf.Bytes(), "singleTx.byte", 0)
		if err := pool.AddRemote(signedTx); err != nil {
			t.Error("Meet error", err)
		}
		queuedTx = append(queuedTx, signedTx)
		queuedTxHash = append(queuedTxHash, signedTx.Hash())
	}
	writeJSON(queuedTx, "queued-txs.json", 0)

	for _, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			t.Fatal("Meet error:", err)
		}
	}
	t.Log("end")

	newState := pool.State()
	t.Log("After trans balance: \n", newState.GetBalance(from), newState.GetBalance(to))
}

func initAccountPool(s *Services, n int, offset int) []*TestAccount {
	accounts := []*TestAccount{}
	for i := offset; i < n; i++ {
		phrase := strconv.Itoa(i)
		acc, err := newAccount(s, phrase)
		if err == nil {
			accounts = append(accounts, acc)
		}
	}

	return accounts
}

type TestAccount struct {
	Address    common.Address `json:"address"`
	Balance    *big.Int       `json:"balance"`
	PassPhrase string         `json:"password"`
	Url        string         `json:"path"`
}

func loadTestAccountsFromFile(testDB string) ([]*TestAccount, bool) {
	dbName := path.Join(rootDir, testDB)
	dat, err := ioutil.ReadFile(dbName)
	if err != nil {
		return nil, false
	}

	accounts := []*TestAccount{}
	err = json.Unmarshal(dat, &accounts)
	if err != nil {
		return nil, false
	}

	return accounts, true
}

func loadLargeScaleTxsFile(testDB string) (types.Transactions, bool) {
	dbName := path.Join(rootDir, testDB)
	dat, err := ioutil.ReadFile(dbName)
	if err != nil {
		return nil, false
	}

	txs := types.Transactions{}
	err = json.Unmarshal(dat, &txs)
	if err != nil {
		return nil, false
	}

	return txs, true
}

func writeJSON(testAccounts interface{}, testDB string, flag int) bool {
	dbName := path.Join(rootDir, testDB)
	dbFile, err := os.Create(dbName)
	if err != nil {
		return false
	}

	defer dbFile.Close()
	data, err := json.Marshal(testAccounts)
	n, err := dbFile.Write(data)
	if n != len(data) || err != nil {
		return false
	}
	dbFile.Sync()
	return true
}

func writeBufferToFile(buf interface{}, testDB string, flag int) bool {
	dbName := path.Join(rootDir, testDB)
	dbFile, err := os.Create(dbName)
	if err != nil {
		return false
	}

	defer dbFile.Close()
	data := buf.([]byte)
	n, err := dbFile.Write(data)
	if n != len(data) || err != nil {
		return false
	}
	dbFile.Sync()
	return true
}

func normalTransferInitialFund(srv *Services, accounts []common.Address, initFund *big.Int) error {
	pool := srv.backend.Ethereum().TxPool()
	currentState := pool.State()
	nonce := currentState.GetNonce(from)
	queuedTxHash := []common.Hash{}
	for i, acc := range accounts {
		// currentState = pool.State()
		key, _ := crypto.GenerateKey()
		tx := transaction(nonce+(uint64)(i), gaslimit, key, acc, initFund)
		signedTx := makeTransaction(srv, &from, "dora.io", tx)
		if err := pool.AddRemote(signedTx); err != nil {
			return err
		}
		queuedTxHash = append(queuedTxHash, signedTx.Hash())
	}
	for _, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			return err
		}
	}

	return nil
}

func simpleTransfer(srv *Services, fromAccount common.Address, password string, toAccount common.Address, initFund *big.Int, bSync bool) (common.Hash, error) {
	pool := srv.backend.Ethereum().TxPool()
	currentState := pool.State()
	nonce := currentState.GetNonce(fromAccount)
	key, _ := crypto.GenerateKey()
	tx := transaction(nonce, gaslimit, key, toAccount, initFund)
	signedTx := makeTransaction(srv, &fromAccount, password, tx)
	if err := pool.AddRemote(signedTx); err != nil {
		return common.Hash{}, err
	}

	if bSync {
		if err := wait(signedTx.Hash(), srv.backend.Ethereum()); err != nil {
			return common.Hash{}, err
		}
	}

	return signedTx.Hash(), nil
}

func fastTransferInitialFundImpl(srv *Services, outAccounts []*TestAccount, idx int, totalFund *big.Int) error {
	if idx >= len(outAccounts) {
		return nil
	}

	destLen := (int)(math.Min((float64)(idx), (float64)(len(outAccounts)-idx)))

	// outAccounts.len < inAccounts.len
	transFund := totalFund.Div(totalFund, big.NewInt(2))
	queuedTxHash := []common.Hash{}
	for i := 0; i < destLen; i++ {
		txHash, err := simpleTransfer(srv, outAccounts[i].Address, outAccounts[i].PassPhrase, outAccounts[idx+i].Address, transFund, false)
		if err != nil {
			return err
		}
		queuedTxHash = append(queuedTxHash, txHash)
	}

	for _, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			return err
		}
	}

	return fastTransferInitialFundImpl(srv, outAccounts, idx+destLen, transFund)
}

func fastTransferInitialFund(srv *Services, accounts []*TestAccount, initFund *big.Int) error {
	transFund := initFund.Mul(initFund, big.NewInt((int64(len(accounts)))))
	simpleTransfer(srv, from, "dora.io", accounts[0].Address, transFund, true)
	return fastTransferInitialFundImpl(srv, accounts, 1, transFund)
}

func updateTestAccountBalance(srv *Services, accounts []*TestAccount) ([]*TestAccount, error) {
	pool := srv.backend.Ethereum().TxPool()
	currentState := pool.State()
	for i := 0; i < len(accounts); i++ {
		accounts[i].Balance = currentState.GetBalance(accounts[i].Address)
		if accounts[i].Balance.Cmp(big.NewInt(0)) == 0 {
			return nil, fmt.Errorf("ERROR: generated accounts[%d].Balance == 0, please check transfer status!", i)
		}
	}
	return accounts, nil
}

func nextPower2(v int) int {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

func initAccountsForPtxTest(srv *Services, n int) ([]*TestAccount, error) {
	m := n
	if (n & (n - 1)) != 0 {
		// return nil, fmt.Errorf("ERROR: Number of accounts %d is not power of 2!", n)
		m = nextPower2(n)
		fmt.Println("Init account should be power of 2, round to ", m)
	}

	// init n accounts
	testAccounts, ok := loadTestAccountsFromFile(accountInfoDB)
	if ok && len(testAccounts) >= n {
		// update balance
		_, err := updateTestAccountBalance(srv, testAccounts)
		return testAccounts[:n], err
	}

	newAccounts := initAccountPool(srv, m, len(testAccounts))
	initFund := ethMath.BigPow(10, 20)

	// normalTransferInitialFund(srv, newAccounts, initFund)
	testAccounts = append(testAccounts, newAccounts...)
	fastTransferInitialFund(srv, testAccounts, initFund)
	_, err := updateTestAccountBalance(srv, testAccounts)

	if err == nil {
		writeJSON(testAccounts, accountInfoDB, 0)
	}

	return testAccounts[:n], err
}

func TestBasicPTX(t *testing.T) {
	srv := initSrv
	defer srv.tmNode.Stop()

	accounts, err := initAccountsForPtxTest(srv, 8)
	if err != nil {
		t.Fatal(err)
	}
	pool := srv.backend.Ethereum().TxPool()

	queuedTxHash := []common.Hash{}
	queuedTx := types.Transactions{}
	currentState := pool.State()
	for idx := 0; idx < len(accounts); idx += 2 {
		key, _ := crypto.GenerateKey()
		sender := accounts[idx].Address
		phrase := accounts[idx].PassPhrase
		reciever := accounts[idx+1].Address
		nonce := currentState.GetNonce(sender)
		tx := transaction(nonce, gaslimit, key, reciever, defaultAmount)
		signedTx := makeTransaction(srv, &sender, phrase, tx)
		queuedTx = append(queuedTx, signedTx)
		queuedTxHash = append(queuedTxHash, signedTx.Hash())
	}

	for _, signedTx := range queuedTx {
		if err := pool.AddRemote(signedTx); err != nil {
			t.Error("Meet error", err)
		}
	}

	for index, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			fmt.Println("test meet error index:", index)
			t.Fatal("Meet error:", err)
		}
	}

	newState := pool.State()
	for idx := 0; idx < len(accounts); idx += 2 {
		acc := accounts[idx+1].Address
		initBalance := accounts[idx+1].Balance
		finalBalance := newState.GetBalance(acc)
		targetBalance := initBalance.Add(initBalance, defaultAmount)
		if finalBalance.Cmp(targetBalance) != 0 {
			t.Fatal("Meet error: final balance of", acc.Hex(), " is", finalBalance, ", not ==", targetBalance)
		} else {
			t.Log("Meet: final balance of", acc.Hex(), " is", finalBalance, ", == target balance ", targetBalance)
		}
	}
}

func TestBasicContract(t *testing.T) {
	srv := initSrv
	defer srv.tmNode.Stop()

	pool := srv.backend.Ethereum().TxPool()
	oldState := pool.State()
	t.Log("Before trans balance: from ", oldState.GetBalance(from), oldState.GetBalance(to))

	nonceFrom := oldState.GetNonce(from)
	nonceTo := oldState.GetNonce(to)
	key, _ := crypto.GenerateKey()

	// step 1. deploy a new smart contract
	tx := newContract(nonceFrom, gaslimit, key, compiledContract)
	signedTx := makeTransaction(srv, &from, "dora.io", tx)
	if err := pool.AddRemote(signedTx); err != nil {
		t.Error("Meet error", err)
	}

	err := wait(signedTx.Hash(), srv.backend.Ethereum())
	if err != nil {
		t.Fatal("Meet error:", err)
	}
	contractAddr, _ := getContractAddress(signedTx.Hash(), srv.backend.Ethereum())

	newState := pool.State()
	t.Log("contract minded, hex address ", contractAddr.Hex())
	t.Log("before deposit balance: \n", newState.GetBalance(from), newState.GetBalance(to), newState.GetBalance(contractAddr))

	// step 2. call smart contract functions.
	key, _ = crypto.GenerateKey()
	nonceFrom++
	tx = callContract(nonceFrom, gaslimit, key, contractAddr, deposit, big.NewInt(111), nil)
	signedTx = makeTransaction(srv, &from, "dora.io", tx)
	if err := pool.AddRemote(signedTx); err != nil {
		t.Fatal("Meet error", err)
	}

	err = wait(signedTx.Hash(), srv.backend.Ethereum())
	if err != nil {
		t.Fatal("Meet error", err)
	}

	key, _ = crypto.GenerateKey()
	tx = callContract(nonceTo, gaslimit, key, contractAddr, deposit, big.NewInt(222), nil)
	signedTx = makeTransaction(srv, &to, "dora.io", tx)
	if err := pool.AddRemote(signedTx); err != nil {
		t.Fatal("Meet error", err)
	}

	err = wait(signedTx.Hash(), srv.backend.Ethereum())
	if err != nil {
		t.Fatal("Meet error", err)
	}

	newState = pool.State()
	t.Log("after deposit balance: \n", newState.GetBalance(from), newState.GetBalance(to), newState.GetBalance(contractAddr))

	// step 3. withdraw a few
	key, _ = crypto.GenerateKey()
	args := common.Hex2Bytes("000000000000000000000000000000000000000000000000000000000000000A")
	nonceTo++
	tx = callContract(nonceTo, gaslimit, key, contractAddr, withdraw, nil, args)
	signedTx = makeTransaction(srv, &to, "dora.io", tx)
	if err := pool.AddRemote(signedTx); err != nil {
		t.Fatal("Meet error", err)
	}

	err = wait(signedTx.Hash(), srv.backend.Ethereum())
	if err != nil {
		t.Fatal("Meet error", err)
	}
	newState = pool.State()
	t.Log("after withdraw balance: \n", newState.GetBalance(from), newState.GetBalance(to), newState.GetBalance(contractAddr))

	// step 4. undeploy smart contract.
	key, _ = crypto.GenerateKey()
	nonceFrom++
	tx = callContract(nonceFrom, gaslimit, key, contractAddr, close, nil, nil)
	signedTx = makeTransaction(srv, &from, "dora.io", tx)
	if err := pool.AddRemote(signedTx); err != nil {
		t.Error("Meet error", err)
	}

	err = wait(signedTx.Hash(), srv.backend.Ethereum())
	if err != nil {
		t.Fatal("Meet error:", err)
	}

	newState = pool.State()
	t.Log("After trans balance: ", newState.GetBalance(from), newState.GetBalance(to))
}

func TestStateDBCommit(t *testing.T) {
	srv := initSrv

	testAccounts, ok := loadTestAccountsFromFile(accountInfoDB)
	if !ok {
		t.Fatal("loadTestAccountsFromFile Fail!")
	}

	txNum := 10000
	if (len(testAccounts) < txNum * 2) {
		t.Log("There are some accounts in cache, result may not accurate.")
	}

	start := time.Now()
	t.Log("Begin time:", start)
	stateDB, _ := stateDBCommit(srv, testAccounts, txNum)
	end := time.Now()
	t.Log("End time:", end)
	t.Log("10000 tx costs :", end.Sub(start))

	// assume no block added at this moment
	bc := srv.backend.Ethereum().BlockChain()
	prevState, _ := bc.State()

	for j := 0; j < txNum; j++ {
		balance := stateDB.GetBalance(testAccounts[j].Address)
		oldBalance := prevState.GetBalance(testAccounts[j].Address)
		targetBalance := oldBalance.Add(oldBalance, defaultAmount)
		if targetBalance.Cmp(balance) != 0 {
			t.Fatal("testAccounts[",j,"] balance is ", balance, "!=", targetBalance, ", stateDB check failed.")
		}
	}
}

func BenchmarkCommit(b *testing.B) {
	srv := initSrv

	testAccounts, ok := loadTestAccountsFromFile(accountInfoDB)
	if !ok {
		b.Fatal("loadTestAccountsFromFile Fail!")
	}
	txNum := 10000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stateDBCommit(srv, testAccounts, txNum)
	}
}

// mock state db operation in one transfer tx
// 1. add balance to from
// 2. add balance to to
// 3. add balance to from (gas fee)
// 4. add balance to coinbase (block bouns)
// 5. commit to db.
func stateDBCommit(srv *Services, accounts []*TestAccount, txNum int) (*state.StateDB, error) {
	db := srv.backend.Ethereum().ChainDb()
	bc := srv.backend.Ethereum().BlockChain()
	stateDB, _ := bc.State()
	
	for j := 0; j < txNum; j++ {
		fromIdx := (2 * j) % len(accounts)
		toIdx := (2 * j + 1) % len(accounts)
		// from change
		stateDB.AddBalance(accounts[fromIdx].Address, defaultAmount)
		// to change
		stateDB.AddBalance(accounts[toIdx].Address, defaultAmount)
		// from's gas change
		stateDB.AddBalance(accounts[fromIdx].Address, defaultAmount)
		// coinbase gets bouns
		stateDB.AddBalance(accounts[0].Address, defaultAmount)
	}
	_, err := stateDB.CommitTo(db, false)
	return stateDB, err
}
