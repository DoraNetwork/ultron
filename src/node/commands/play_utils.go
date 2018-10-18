package commands

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"math/rand"
	"path"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth"

	rpcClient "github.com/tendermint/tendermint/rpc/client"
)

var (
	defaultAmount   = big.NewInt(1)
	gasprice        = big.NewInt(2.5e9) // should be higher than 2gwei (asked by ethermint)
	gaslimit        = big.NewInt(5e6)
	genesisAccounts = 128
    accountInfoDB   = "simple-test-info.json" // a file to save some test info
)

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

type TestAccount struct {
	Address    common.Address `json:"address"`
	Balance    *big.Int       `json:"balance"`
	PassPhrase string         `json:"password"`
	Url        string         `json:"path"`
}

func loadTestAccountsFromFile(rootDir, testDB string) ([]*TestAccount, bool) {
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

func initAccountsForPtxTest(srv *Services, rootDir string, n int) ([]*TestAccount, error) {
	m := n
	if (n & (n - 1)) != 0 {
		m = nextPower2(n)
		fmt.Println("Init account should be power of 2, round to ", m)
	}

	// init n accounts
	testAccounts, ok := loadTestAccountsFromFile(rootDir, accountInfoDB)
	if ok && len(testAccounts) >= n {
		// update balance
		_, err := updateTestAccountBalance(srv, testAccounts)
		return testAccounts[:n], err
	}

	// newAccounts := initAccountPool(srv, m, len(testAccounts))
	// initFund := ethMath.BigPow(10, 20)

	// testAccounts = append(testAccounts, newAccounts...)
	// fastTransferInitialFund(srv, testAccounts, initFund)
	// _, err := updateTestAccountBalance(srv, testAccounts)

	// if err == nil {
	// 	writeJSON(testAccounts, accountInfoDB, 0)
	// }

	return testAccounts[:n], fmt.Errorf("ERROR: load %s Failed!", accountInfoDB)
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

func getTransactionReceipt(txHash common.Hash, eth *eth.Ethereum) (*types.Receipt, error) {
	receipt := core.GetReceipt(eth.ChainDb(), txHash)
	if receipt == nil {
		return nil, fmt.Errorf("Receipt not found for transaction" + txHash.Hex())
	}
	return receipt, nil
}

func transaction(nonce uint64, gaslimit *big.Int, key *ecdsa.PrivateKey, to common.Address, amount *big.Int) *types.Transaction {
	tx := types.NewTransaction(nonce, to, amount, gaslimit, gasprice, nil)
	return tx
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
	repeat := 10
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

func waitTxsAsync(srv *Services, queuedTxHash []common.Hash) error {
	for idx, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			return fmt.Errorf("Meet error: %s, idx := %d .", err, idx)
		}
	}

	return nil
}

func prepareTXs(srv *Services, txCnt, accOffset int, accounts []*TestAccount) (txsBytes [][]byte, txs types.Transactions, queuedTxHash []common.Hash, err error) {
	pool := srv.backend.Ethereum().TxPool()
	state := pool.State()
	
	fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Prepare Tx")
	for i := 0; i < txCnt; i++ {
		nonce := state.GetNonce(accounts[i].Address)
		key, _ := crypto.GenerateKey()
		tx := transaction(nonce, gaslimit, key, accounts[(i + accOffset) % txCnt].Address, defaultAmount)
		signedTx := makeTransaction(srv, &accounts[i].Address, accounts[i].PassPhrase, tx)
		txs = append(txs, signedTx)
		buf := new(bytes.Buffer)
		signedTx.EncodeRLP(buf)
		txsBytes = append(txsBytes, buf.Bytes())
		queuedTxHash = append(queuedTxHash, signedTx.Hash())
	}

	return txsBytes, txs, queuedTxHash, nil
}

func prepareTXsAsync(srv *Services, txCnt int, accounts []*TestAccount) (chan types.Transactions, error) {
	txsCh := make(chan types.Transactions)
	accOffset := (rand.Int() % txCnt) + 1

	go func() {	
		var nonceOffset uint64
		for ;; {
			pool := srv.backend.Ethereum().TxPool()
			state := pool.State()
			txs := types.Transactions{}

			// fmt.Println("txnCnt", txCnt, "len(accoutns)", len(accounts))
			for i := 0; i < len(accounts); i++ {
				nonce := state.GetNonce(accounts[i].Address) + nonceOffset
				key, _ := crypto.GenerateKey()
				tx := transaction(nonce, gaslimit, key, accounts[(i + accOffset) % txCnt].Address, defaultAmount)
				// fmt.Println("i", i, "&accounts[i].Address", &accounts[i].Address, "accounts[i].PassPhrase", accounts[i].PassPhrase)
				signedTx := makeTransaction(srv, &accounts[i].Address, accounts[i].PassPhrase, tx)
				txs = append(txs, signedTx)
			}

			accOffset++
			nonceOffset++
			// fmt.Println("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ generate", txCnt, "txs in go routine with offset :=", accOffset)
			txsCh <- txs
		}
	}()

	return txsCh, nil
}


func createRemoteClientConnections(N int) []*rpcClient.HTTP {
	// if N < 2 {
	// 	N = 2
	// }

	httpClients := make([]*rpcClient.HTTP, N)
	for i := 0 ; i < N; i++ {
		httpClients[i] = rpcClient.NewHTTP("tcp://127.0.0.1:46657", "/websocket")
	}
	return httpClients
}

func addTxsToHTTPClientAsync(httpClients []*rpcClient.HTTP, txs [][]byte) *sync.WaitGroup {
	remoteClientCnt := len(httpClients)
	wg := sync.WaitGroup{}
	txCntFromRemote := len(txs) / remoteClientCnt

	i := 0
	remoteId := 0
	for ; i + txCntFromRemote < len(txs); i += txCntFromRemote {
		wg.Add(1)
		txsFromRemote := txs[i : i + txCntFromRemote]
		remote := httpClients[remoteId]
		remoteId++
		go func () {
			// frmAddr, _ :=tx.From(pool.Signer())
			for j := 0; j < len(txsFromRemote); j++ {
				_, err := remote.BroadcastTxAsync(txsFromRemote[j])
				if (err != nil) {
					fmt.Println("ERROR: BroadcastTxAsync error:", err)
				}
			}

			wg.Done()
		}()
	}

	wg.Add(1)
	go func () {
		// handle rest if exist
		txsFromRemote := txs[i:]
		for j := 0; j < len(txsFromRemote); j++ {
			_, err := httpClients[0].BroadcastTxAsync(txsFromRemote[j])
			if (err != nil) {
				fmt.Println("ERROR: BroadcastTxAsync error:", err)
			}
		}
		wg.Done()
	}()
	return &wg
}
