package ethereum

import (
	"fmt"
	//"time"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	//"github.com/ethereum/go-ethereum/log"
	//"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/params"
	abciTypes "github.com/tendermint/abci/types"

	emtTypes "github.com/dora/ultron/backend/types"
	"github.com/dora/ultron/errors"
	//"github.com/dora/ultron/const"
	emtConfig "github.com/dora/ultron/node/config"
)

//----------------------------------------------------------------------
// EthState manages concurrent access to the intermediate workState object
// The ethereum tx pool fires TxPreEvent in a go-routine,
// and the miner subscribes to this in another go-routine and processes the tx onto
// an intermediate state. We used to use `unsafe` to overwrite the miner, but this
// didn't work because it didn't affect the already launched go-routines.
// So instead we introduce the Pending API in a small commit in go-ethereum
// so we don't even start the miner there, and instead manage the intermediate state from here.
// In the same commit we also fire the TxPreEvent synchronously so the order is preserved,
// instead of using a go-routine.

type EthState struct {
	ptxEnabled bool

	ethereum       *eth.Ethereum
	ethConfig      *eth.Config
	txExecutor     *TransactionExecutor
	stateProcessor *StateProcessor

	mtx  sync.Mutex
	work workState // latest working state
}

// After NewEthState, call SetEthereum and SetEthConfig.
func NewEthState() *EthState {
	ptxEnabled := true
	testConfig, _ := emtConfig.ParseConfig()
	if testConfig != nil {
		if testConfig.TestConfig.DisablePtx {
			ptxEnabled = false
		}
	}
	var txExecutor *TransactionExecutor
	if ptxEnabled {
		txExecutor = newTransactionExecutor()
	}
	return &EthState{
		ethereum:   nil, // set with SetEthereum
		ethConfig:  nil, // set with SetEthConfig
		ptxEnabled: ptxEnabled,
		txExecutor: txExecutor,
	}
}

func (es *EthState) IsPtxEnabled() bool {
	return es.ptxEnabled
}

func (es *EthState) SetConfig(ethereum *eth.Ethereum, ethConfig *eth.Config) {
	es.ethereum = ethereum
	es.ethConfig = ethConfig
	if es.IsPtxEnabled() {
		es.txExecutor.setConfig(es.ethereum, es.ethConfig)
		es.stateProcessor = NewStateProcessor(ethereum.ApiBackend.ChainConfig(), ethereum.BlockChain(), ethereum.BlockChain().Engine())
		ethereum.BlockChain().SetProcessor(es.stateProcessor)
	}
}

func (es *EthState) UpdateProposer(isProposer bool) {
	if es.IsPtxEnabled() {
		es.txExecutor.UpdateProposer(isProposer)
	}
}

func (es *EthState) CheckTx(tx *ethTypes.Transaction) abciTypes.ResponseCheckTx {
	// es.ethereum.EventMux().Post(TxPreEvent{Tx:tx, Local:false})
	//TODO:another case, only broadcast
	return abciTypes.ResponseCheckTx{Code: abciTypes.CodeTypeOK}
}

// Execute the transaction.
func (es *EthState) DeliverTx(tx *ethTypes.Transaction) abciTypes.ResponseDeliverTx {
	es.mtx.Lock()
	defer es.mtx.Unlock()

	blockchain := es.ethereum.BlockChain()
	chainConfig := es.ethereum.ApiBackend.ChainConfig()
	blockHash := common.Hash{}
	if !es.IsPtxEnabled() {
		es.work.transactions = append(es.work.transactions, tx)
		return abciTypes.ResponseDeliverTx{Code: abciTypes.CodeTypeOK}
	}
	return es.work.deliverTx(blockchain, es.ethConfig, chainConfig, blockHash, tx)
}

func (es *EthState) DeliverPtx(ptx *ParalleledTransaction) abciTypes.ResponseDeliverTx {
	if !es.IsPtxEnabled() {
		return abciTypes.ResponseDeliverTx{Code: errors.ErrorTypeInternalErr}
	}
	es.mtx.Lock()
	defer es.mtx.Unlock()

	// fmt.Println("deliver ptx", ptx.Hash().Hex())
	if es.txExecutor.IsValidator() {
		wg := &sync.WaitGroup{}
		ndag := &NotifiableDag{ptx: ptx, wg: wg}
		wg.Add(1)
		es.txExecutor.dispatchDagCh <- ndag
		wg.Wait()
		fmt.Println("validator verify ptx done")
	}
	if !es.txExecutor.DeliverTx(ptx) {
		return abciTypes.ResponseDeliverTx{Code: errors.ErrorTypeInternalErr}
	}

	blockchain := es.ethereum.BlockChain()
	chainConfig := es.ethereum.ApiBackend.ChainConfig()
	blockHash := common.Hash{}
	return es.work.deliverPtx(blockchain, es.ethConfig, chainConfig, blockHash, ptx)
}

// called by ultron tx only in deliver_tx
func (es *EthState) AddNonce(addr common.Address) {
	es.mtx.Lock()
	defer es.mtx.Unlock()

	es.work.state.SetNonce(addr, es.work.state.GetNonce(addr)+1)
}

// Accumulate validator rewards.
func (es *EthState) AccumulateRewards(strategy *emtTypes.Strategy) {
	es.mtx.Lock()
	defer es.mtx.Unlock()

	es.work.accumulateRewards(strategy)
}

// Commit and reset the work.
func (es *EthState) Commit(receiver common.Address) (common.Hash, error) {
	es.mtx.Lock()
	defer es.mtx.Unlock()
	if es.IsPtxEnabled() {
		es.work.state = es.txExecutor.commitState()
	}
	blockHash, err := es.work.commit(es.ethereum.BlockChain(), es.ethereum.ChainDb())
	if err != nil {
		return common.Hash{}, err
	}

	err = es.resetWorkState(receiver)
	if err != nil {
		return common.Hash{}, err
	}

	return blockHash, err
}

func (es *EthState) EndBlock() {
}

func (es *EthState) ResetWorkState(receiver common.Address) error {
	es.mtx.Lock()
	defer es.mtx.Unlock()

	return es.resetWorkState(receiver)
}

func (es *EthState) resetWorkState(receiver common.Address) error {

	blockchain := es.ethereum.BlockChain()
	state, err := blockchain.State()
	if err != nil {
		return err
	}

	currentBlock := blockchain.CurrentBlock()
	ethHeader := newBlockHeader(receiver, currentBlock, es.ethereum.ApiBackend.ChainConfig())
	if es.IsPtxEnabled() {
		es.txExecutor.makeCurrent(es.ethereum, es.ethConfig, ethHeader, currentBlock, state)
	}
	es.work = workState{
		ethereum:        es.ethereum,
		ethConfig:       es.ethConfig,
		header:          ethHeader,
		parent:          currentBlock,
		state:           state,
		txIndex:         0,
		totalUsedGas:    big.NewInt(0),
		totalUsedGasFee: big.NewInt(0),
		txExecutor:      es.txExecutor,
		stateProcessor:  es.stateProcessor,
		gp:              new(core.GasPool).AddGas(ethHeader.GasLimit),
	}
	return nil
}

func (es *EthState) UpdateHeaderWithTimeInfo(
	config *params.ChainConfig, parentTime uint64, numTx uint64) {

	es.mtx.Lock()
	defer es.mtx.Unlock()
	if es.IsPtxEnabled() {
		es.txExecutor.beginBlock()
	}
	es.work.updateHeaderWithTimeInfo(config, parentTime, numTx)
}

func (es *EthState) GasLimit() big.Int {
	return big.Int(*es.work.gp)
}

//----------------------------------------------------------------------
// Implements: miner.Pending API (our custom patch to go-ethereum)

// Return a new block and a copy of the state from the latest work.
// #unstable
func (es *EthState) Pending() (*ethTypes.Block, *state.StateDB) {
	es.mtx.Lock()
	defer es.mtx.Unlock()

	return ethTypes.NewBlock(
		es.work.header,
		es.work.transactions,
		nil,
		es.work.receipts,
	), es.work.state.Copy()
}

//----------------------------------------------------------------------
//

// The work struct handles block processing.
// It's updated with each DeliverTx and reset on Commit.
type workState struct {
	ethereum  *eth.Ethereum
	ethConfig *eth.Config

	header *ethTypes.Header
	parent *ethTypes.Block
	state  *state.StateDB

	txExecutor     *TransactionExecutor
	stateProcessor *StateProcessor

	txIndex      int
	transactions []*ethTypes.Transaction
	receipts     ethTypes.Receipts
	allLogs      []*ethTypes.Log

	totalUsedGas    *big.Int
	totalUsedGasFee *big.Int
	gp              *core.GasPool
}

// nolint: unparam
func (ws *workState) accumulateRewards(strategy *emtTypes.Strategy) {

	ethash.AccumulateRewards(ws.state, ws.header, []*ethTypes.Header{})
	ws.header.GasUsed = ws.totalUsedGas
}

// Runs ApplyTransaction against the ethereum blockchain, fetches any logs,
// and appends the tx, receipt, and logs.
func (ws *workState) deliverTx(blockchain *core.BlockChain, config *eth.Config,
	chainConfig *params.ChainConfig, blockHash common.Hash,
	tx *ethTypes.Transaction) abciTypes.ResponseDeliverTx {

	ws.state.Prepare(tx.Hash(), blockHash, ws.txIndex)
	receipt, usedGas, err := core.ApplyTransaction(
		chainConfig,
		blockchain,
		nil, // defaults to address of the author of the header
		ws.gp,
		ws.state,
		ws.header,
		tx,
		ws.totalUsedGas,
		vm.Config{EnablePreimageRecording: config.EnablePreimageRecording},
	)
	if err != nil {
		return abciTypes.ResponseDeliverTx{Code: errors.ErrorTypeInternalErr, Log: err.Error()}
	}

	usedGasFee := big.NewInt(0).Mul(usedGas, tx.GasPrice())
	ws.totalUsedGasFee.Add(ws.totalUsedGasFee, usedGasFee)

	logs := ws.state.GetLogs(tx.Hash())

	ws.txIndex++

	// The slices are allocated in updateHeaderWithTimeInfo
	ws.transactions = append(ws.transactions, tx)
	ws.receipts = append(ws.receipts, receipt)
	ws.allLogs = append(ws.allLogs, logs...)

	return abciTypes.ResponseDeliverTx{Code: abciTypes.CodeTypeOK}
}

func (ws *workState) deliverPtx(blockchain *core.BlockChain, config *eth.Config,
	chainConfig *params.ChainConfig, blockHash common.Hash,
	ptx *ParalleledTransaction) abciTypes.ResponseDeliverTx {
	etxs := ws.txExecutor.getExecutedTransactions(ptx)
	for _, etx := range etxs {
		if !isEthTx(etx.tx) {
			continue
		}
		tx := etx.tx
		ws.totalUsedGas.Add(ws.totalUsedGas, etx.receipt.GasUsed)

		//Assign CumulativeGasUsed
		etx.receipt.CumulativeGasUsed = ws.totalUsedGas

		ws.transactions = append(ws.transactions, tx)
		ws.receipts = append(ws.receipts, etx.receipt)
		for _, log := range etx.receipt.Logs {
			log.TxIndex = uint(ws.txIndex)
		}
		ws.allLogs = append(ws.allLogs, etx.receipt.Logs...)

		ws.txIndex++
	}
	return abciTypes.ResponseDeliverTx{Code: abciTypes.CodeTypeOK}
}

// Commit the ethereum state, update the header, make a new block and add it to
// the ethereum blockchain. The application root hash is the hash of the
// ethereum block.
func (ws *workState) commit(blockchain *core.BlockChain, db ethdb.Database) (common.Hash, error) {
	// Commit ethereum state and update the header.
	hashArray, err := ws.state.CommitTo(db, false) // XXX: ugh hardforks
	if err != nil {
		return common.Hash{}, err
	}

	ws.header.Root = hashArray

	for _, log := range ws.allLogs {
		log.BlockHash = hashArray
	}

	// Create block object and compute final commit hash (hash of the ethereum
	// block).
	block := ethTypes.NewBlock(ws.header, ws.transactions, nil, ws.receipts)
	blockHash := block.Hash()

	// Save the block to disk.
	// log.Info("Committing block", "stateHash", hashArray, "blockHash", blockHash)
	if ws.stateProcessor != nil {
		ws.stateProcessor.Prepare(ws.state, ws.receipts, ws.allLogs)
	}
	_, err = blockchain.InsertChain([]*ethTypes.Block{block})
	if err != nil {
		// log.Info("Error inserting ethereum block in chain", "err", err)
		return common.Hash{}, err
	}
	return blockHash, err
}

func (ws *workState) updateHeaderWithTimeInfo(
	config *params.ChainConfig, parentTime uint64, numTx uint64) {

	lastBlock := ws.parent
	parentHeader := &ethTypes.Header{
		Difficulty: lastBlock.Difficulty(),
		Number:     lastBlock.Number(),
		Time:       lastBlock.Time(),
	}
	ws.header.Time = new(big.Int).SetUint64(parentTime)
	ws.header.Difficulty = ethash.CalcDifficulty(config, parentTime, parentHeader)
	ws.transactions = make([]*ethTypes.Transaction, 0, numTx)
	ws.receipts = make([]*ethTypes.Receipt, 0, numTx)
	ws.allLogs = make([]*ethTypes.Log, 0, numTx)
}

//----------------------------------------------------------------------

// Create a new block header from the previous block.
func newBlockHeader(receiver common.Address, prevBlock *ethTypes.Block, config *params.ChainConfig) *ethTypes.Header {
	tstart := time.Now()
	tstamp := tstart.Unix()
	return &ethTypes.Header{
		Number:     prevBlock.Number().Add(prevBlock.Number(), big.NewInt(1)),
		ParentHash: prevBlock.Hash(),
		GasLimit:   core.CalcGasLimit(prevBlock),
		Difficulty: ethash.CalcDifficulty(config, prevBlock.Time().Uint64(), prevBlock.Header()),
		Time:       big.NewInt(tstamp),
		Coinbase:   receiver,
	}
}
