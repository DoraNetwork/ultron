package ethereum

import (
	"bytes"
	"container/list"
	"fmt"
	"io"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/event"
	//"github.com/ethereum/go-ethereum/log"
	//"github.com/ethereum/go-ethereum/core/types"

	emtConfig "github.com/dora/ultron/node/config"
	"github.com/ethereum/go-ethereum/crypto/sha3"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

//----------------------------------------------------------------------
const NODE_TYPE_UNKNOWN int = 0
const NODE_TYPE_PROPOSER int = 1
const NODE_TYPE_VALIDATOR int = 2

//Must large than 1000, otherwise tendermint may report same timestamp for two block
//timestamp is unixstamp(s)
var CYCLE_PERIOD uint = 1100

const CONSENSUS_WAIT_TX bool = true

const MAX_CPU_NUM = 1
const THREAD_MAX_PENDING_TX_SIZE = 4000

//WAIT_MIN_TX=true, Performance test case
const WAIT_MIN_TX bool = false
const MIN_TX_COUNT int = 16383

var firstDispatch bool = true

//Performance Optimize Cases
const OPT_REUSE_STATE bool = true
const TEST_CONTRACT bool = true

var TEST_VALIDATOR bool = true

var timeTrace = NewTimeTrace()

var broadcastPtxHash = true
var deliverPtxHash = true
var startBeginBlock = false

// ParalleledTransaction.
type ParalleledTransaction struct {
	data ParalleledTransactionData

	// cache
	hash atomic.Value
	size atomic.Value
}

type ParalleledTransactionData struct {
	TxIds []common.Hash
	Txs   [][]byte
	Dag   *Dag
}

type NotifiableDag struct {
	ptx *ParalleledTransaction
	wg  *sync.WaitGroup
}

func rlpHash(x interface{}) (h common.Hash) {
	hw := sha3.NewKeccak256()
	rlp.Encode(hw, x)
	hw.Sum(h[:0])
	return h
}

func isEthTx(tx *ethTypes.Transaction) bool {
	zero := big.NewInt(0)
	return tx.Data() == nil ||
		tx.GasPrice().Cmp(zero) != 0 ||
		tx.Gas().Cmp(zero) != 0 ||
		tx.Value().Cmp(zero) != 0 ||
		tx.To() != nil
}

func (tx *ParalleledTransaction) RawTxs() [][]byte {
	return tx.data.Txs
}

func (tx *ParalleledTransaction) Dag() *Dag {
	return tx.data.Dag
}

// DecodeRLP implements rlp.Encoder
func (tx *ParalleledTransaction) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &tx.data)
}

func (tx *ParalleledTransaction) Hash() common.Hash {
	if hash := tx.hash.Load(); hash != nil {
		return hash.(common.Hash)
	}
	v := rlpHash(tx)
	tx.hash.Store(v)
	return v
}

// DecodeRLP implements rlp.Decoder
func (tx *ParalleledTransaction) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	err := s.Decode(&tx.data)
	if err == nil {
		tx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}

	return err
}

func encodeTxRLP(tx *ethTypes.Transaction) ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := tx.EncodeRLP(buf); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// rlp decode an etherum transaction
func decodeTx(txBytes []byte) (*ethTypes.Transaction, error) {
	tx := new(ethTypes.Transaction)
	rlpStream := rlp.NewStream(bytes.NewBuffer(txBytes), 0)
	if err := tx.DecodeRLP(rlpStream); err != nil {
		return nil, err
	}
	return tx, nil
}

func (ptx *ParalleledTransaction) fillTxs(allTxs [][]*ExecutedTransaction) {
	var allTxIds [][]common.Hash
	for _, etxs := range allTxs {
		var txIds []common.Hash
		for _, etx := range etxs {
			txIds = append(txIds, etx.tx.Hash())
			if broadcastPtxHash && (!startBeginBlock || deliverPtxHash) {
				ptx.data.TxIds = append(ptx.data.TxIds, etx.tx.Hash())
			} else {
				txrlp, err := encodeTxRLP(etx.tx)
				if err == nil {
					ptx.data.Txs = append(ptx.data.Txs, txrlp)
				}
			}
		}
		if txIds != nil && len(txIds) > 0 {
			allTxIds = append(allTxIds, txIds)
		}
	}
	ptx.data.Dag = NewDag(allTxIds)
}

type CycleContext struct {
	ptx  *ParalleledTransaction
	ws   *state.StateDB
	prev *CycleContext
	next *CycleContext
}

type ExecutingTransaction struct {
	tx     *ethTypes.Transaction
	thread *threadContext
}

type ExecutedTransaction struct {
	tx *ethTypes.Transaction

	receipt *ethTypes.Receipt
	// logs already included in receipt
	// logs    []*ethTypes.Log
	tracer *ContractTrace
}

type TxPreEvent struct {
	Tx    *ethTypes.Transaction
	Local bool
}

type PtxPreEvent struct{ Ptx *ParalleledTransaction }

func newTransactionExecutor() *TransactionExecutor {
	e := &TransactionExecutor{
		cycleDuration: 5 * 1000 * 1000,
	} // 1s
	// e.init()
	// go e.dispatchLoop()
	// go e.cycleLoop()

	testConfig, _ := emtConfig.ParseConfig()
	if testConfig != nil {
		if !testConfig.TestConfig.UsePtxHash {
			broadcastPtxHash = false
		}
		if testConfig.TestConfig.BuildFullBlock {
			deliverPtxHash = false
		}
		if !testConfig.TestConfig.ForceValidator {
			TEST_VALIDATOR = false
		}
		CYCLE_PERIOD = testConfig.TestConfig.PtxCyclePeriod
		if CYCLE_PERIOD == 0 {
			CYCLE_PERIOD = 1100
		}
	}
	return e
}

type addressExecuteCounter struct {
	//[threadContextIndex]txNum
	counter map[int16]int16
}

type TransactionExecutor struct {
	ethereum  *eth.Ethereum
	ethConfig *eth.Config
	config    *params.ChainConfig

	stopped bool

	header       *ethTypes.Header
	parent       *ethTypes.Block
	state        *state.StateDB
	currentState *state.StateDB
	currentRoot  common.Hash
	signer       ethTypes.Signer

	txPool           *core.TxPool
	executingTxsInfo map[common.Address]*threadContext
	executingTxs     map[common.Hash]*ethTypes.Transaction
	executedTxs      map[common.Hash]*ExecutedTransaction
	txCache          map[common.Hash]*ethTypes.Transaction
	threads          []*threadContext

	txSub    *event.TypeMuxSubscription
	eventMux *event.TypeMux

	quit            chan struct{}
	resetTickerCh   chan struct{}
	dispatchTxChain chan struct{}
	dispatchDagCh   chan *NotifiableDag

	stopCycleChain    chan *sync.WaitGroup
	stopDispatchChain chan *sync.WaitGroup
	dispatchPausing   bool
	cyclePausing      bool

	cycleTicker *time.Timer

	currentCycleCtx  *CycleContext
	firstCycleCtx    *CycleContext
	selectedCycleCtx *CycleContext
	nodeType         int

	cycleDuration time.Duration
	//TODO:really need?
	mtx         sync.Mutex
	executedMtx sync.Mutex
}

func (te *TransactionExecutor) getExecutedTransactions(ptx *ParalleledTransaction) []*ExecutedTransaction {
	var etxs []*ExecutedTransaction
	//TODO:get executedTransaction from dag
	// for hash, etx := range te.executedTxs {
	// 	fmt.Println("hash", hash.String())
	// 	fmt.Println("tx", etx.tx.String())
	// }
	te.lock("getExecutedTransactions")
	defer te.unlock("getExecutedTransactions")
	if deliverPtxHash {
		for _, txid := range ptx.data.TxIds {
			if etx, ok := te.executedTxs[txid]; ok {
				etxs = append(etxs, etx)
			} else {
				fmt.Println("no find executed tx for ", txid)
			}
		}
	} else {
		for _, tx := range ptx.data.Txs {
			ethTx, err := decodeTx(tx)
			if err == nil {
				if etx, ok := te.executedTxs[ethTx.Hash()]; ok {
					etxs = append(etxs, etx)
				} else {
					fmt.Println("no find executed tx for ", tx)
				}
			} else {
				fmt.Println("decode tx fail ", tx)
			}
		}
	}
	return etxs
}

func (te *TransactionExecutor) getExecutedTransaction(txid common.Hash) *ExecutedTransaction {
	if etx, ok := te.executedTxs[txid]; ok {
		return etx
	} else {
		return nil
	}
}

func (te *TransactionExecutor) stopCycleTicker() {
	te.cycleTicker.Stop()
}

func (te *TransactionExecutor) resetCycleTicker() {
	// te.cycleTicker = time.NewTicker(time.Duration(CYCLE_PERIOD) * time.Millisecond)
	te.lock("resetCycleTicker")
	defer te.unlock("resetCycleTicker")
	te.resetCycleTickerLocked()
}

func (te *TransactionExecutor) resetCycleTickerLocked() {
	if te.cycleTicker == nil {
		te.cycleTicker = time.NewTimer(time.Millisecond * time.Duration(CYCLE_PERIOD))
	} else {
		te.cycleTicker.Reset(time.Millisecond * time.Duration(CYCLE_PERIOD))
	}
}

func (te *TransactionExecutor) setConfig(ethereum *eth.Ethereum,
	ethConfig *eth.Config) {
	if ethereum != nil {
		te.ethereum = ethereum
		te.config = ethereum.ApiBackend.ChainConfig()
		te.signer = ethTypes.NewEIP155Signer(te.config.ChainId)
		// delay init as ethereum is set here.
	} else {
		te.ethereum = nil
		te.config = nil
		te.signer = nil
	}
	te.ethConfig = ethConfig
	if te.ethConfig != nil && te.ethereum != nil {
		te.init()
	}
}

func (te *TransactionExecutor) State() (*state.StateDB, error) {
	return te.currentState.Copy(), nil
}

func (te *TransactionExecutor) GasLimit() *big.Int {
	return te.header.GasLimit
}

func (te *TransactionExecutor) init() {
	te.resetCycleTicker()
	te.quit = make(chan struct{}, 1)
	te.resetTickerCh = make(chan struct{}, 1)
	te.dispatchTxChain = make(chan struct{}, 1)
	te.dispatchDagCh = make(chan *NotifiableDag, 1)
	te.stopCycleChain = make(chan *sync.WaitGroup, 1)
	te.stopDispatchChain = make(chan *sync.WaitGroup, 1)

	if te.ethereum != nil {
		te.txSub = te.ethereum.EventMux().Subscribe(TxPreEvent{})
		threads := MAX_CPU_NUM //runtime.NumCPU()
		for th := 0; th < threads; th++ {
			tcontext := &threadContext{
				index:          th,
				requestTxChain: te.dispatchTxChain,
				quit:           make(chan struct{}, 1),
				waitTxChan:     make(chan struct{}, 1),
				fenceChan:      make(chan *sync.WaitGroup, 1),
				waitEmptyChan:  make(chan *sync.WaitGroup, 1),
				executingTxs:   &list.List{},
			}
			go tcontext.loop()
			te.threads = append(te.threads, tcontext)
		}
	} else {
		fmt.Println("ERROR: ethereum is nil.")
	}
	go te.dispatchLoop()
	go te.cycleLoop()
}

// // rescheduleFetch resets the specified fetch timer to the next announce timeout.
// func (te *TransactionExecutor) rescheduleCycle() {
// 	te.cycleTicker.After(te.cycleDuration)
// }

func (te *TransactionExecutor) cycleLoop() {
	for {
		select {
		case wg := <-te.stopCycleChain:
			fmt.Println("response stop cycle")
			wg.Done()

		case <-te.quit:
			// executor terminating, abort all operations
			return

		case <-te.cycleTicker.C:
			//Trigger next cycle
			te.ResumeCycle()
			ptx := te.processOneCycle(false)
			if CONSENSUS_WAIT_TX || ptx == nil {
				te.Resume()
			}
			te.resetCycleTicker()
		}
	}
}

func (te *TransactionExecutor) applyPtxState(state *state.StateDB, ptx *ParalleledTransaction) {
	for _, txid := range ptx.data.TxIds {
		etx := te.getExecutedTransaction(txid)
		if !isEthTx(etx.tx) {
			continue
		}
		changes := etx.tracer.ChangedValues()
		for contract, storage := range changes {
			for k, v := range storage {
				state.SetState(contract, k, v)
			}
		}

		codes := etx.tracer.CreatedContracts()

		for adr, code := range codes {
			state.SetCode(adr, code)
		}

		balances := etx.tracer.ChangedBalances()
		for adr, balance := range balances {
			// fmt.Println("set adr:",adr , " balance:", balance)
			state.SetBalance(adr, balance)
		}
		msg, err := etx.tx.AsMessage(te.signer)
		if err != nil {
			//TODO:handle exception
			return
		}
		state.SetNonce(msg.From(), etx.tx.Nonce()+1)
		// root := state.IntermediateRoot(false)
		// etx.receipt.PostState = common.CopyBytes(root.Bytes())
	}
}

func (te *TransactionExecutor) applyTxsState(state *state.StateDB, etxs []*ExecutedTransaction) {
	if etxs == nil {
		return
	}
	for _, etx := range etxs {
		te.applyTxState(state, etx)
	}
}

func (te *TransactionExecutor) applyTxState(state *state.StateDB, etx *ExecutedTransaction) {
	if !isEthTx(etx.tx) {
		return
	}
	if etx == nil {
		fmt.Println("Not found executed tx for tx,", etx.tx)
		return
	}
	// fmt.Println("ptx selected tx,", etx.tx.Hash().Hex())
	changes := etx.tracer.ChangedValues()
	for contract, storage := range changes {
		for k, v := range storage {
			state.SetState(contract, k, v)
		}
	}

	codes := etx.tracer.CreatedContracts()

	for adr, code := range codes {
		state.SetCode(adr, code)
	}

	balances := etx.tracer.ChangedBalances()
	for adr, balance := range balances {
		// fmt.Println("apply addr:", adr.Hex(), " balance:", balance)
		state.SetBalance(adr, balance)
	}
	msg, err := etx.tx.AsMessage(te.signer)
	if err != nil {
		//TODO:handle exception
		return
	}
	state.SetNonce(msg.From(), etx.tx.Nonce()+1)
	// root := state.IntermediateRoot(false)
	// etx.receipt.PostState = common.CopyBytes(root.Bytes())
}

func (te *TransactionExecutor) lock(info string) {
	// fmt.Println("te before lock", info)
	te.mtx.Lock()
	// fmt.Println("te lock", info)
}

func (te *TransactionExecutor) UpdateProposer(isProposer bool) {
	if isProposer {
		te.nodeType = NODE_TYPE_PROPOSER
	} else {
		te.nodeType = NODE_TYPE_VALIDATOR
	}
}

func (te *TransactionExecutor) IsValidator() bool {
	if TEST_VALIDATOR {
		return true
	}
	return te.nodeType == NODE_TYPE_VALIDATOR
}

func (te *TransactionExecutor) unlock(info string) {
	te.mtx.Unlock()
	// fmt.Println("te unlock", info)
}

func (te *TransactionExecutor) processOneCycle(validator bool) *ParalleledTransaction {
	// te.mtx.Lock()
	// defer te.mtx.Unlock()
	if te.cyclePausing && !validator {
		return nil
	}
	te.Pause()
	fmt.Println("one cycle", time.Now(), validator)
	if te.currentState == nil {
		fmt.Println("state is nil")
		return nil
	}

	timeTrace.start("processOneCycle")
	defer timeTrace.endWithPrint("processOneCycle")

	currentRoot := te.currentRoot

	ptx, state, selectedTxs := te.generatePtx(currentRoot, te.currentState.GetDataBase())

	if ptx == nil {
		fmt.Println("generate ptx null", time.Now())
		// te.updateState()
		return nil
	}

	if state == nil {
		fmt.Println("generate ptx state nil", time.Now())
		// te.updateState()
		return nil
	}

	te.lock("processOneCycle")
	defer te.unlock("processOneCycle")
	if currentRoot != te.currentRoot {
		//TODO:Header may change, so executed tx may useless
		fmt.Println("cycle context has changed, skip all data", time.Now())
		return nil
	}

	cycleCtx := &CycleContext{prev: te.currentCycleCtx, ptx: ptx, ws: state}
	if te.firstCycleCtx == nil {
		te.firstCycleCtx = cycleCtx
	}

	cycleCtx.prev = te.currentCycleCtx
	if te.currentCycleCtx != nil {
		te.currentCycleCtx.next = cycleCtx
	}
	te.currentCycleCtx = cycleCtx

	//executedTxs
	count := 0
	for _, etxs := range selectedTxs {
		for _, etx := range etxs {
			count++
			// fmt.Println("selectedTx", etx.tx.Hash().Hex())
			te.executedTxs[etx.tx.Hash()] = etx
		}
	}
	fmt.Println("selectedTxs length:", count, time.Now(), ptx.Hash().Hex())
	te.updateStateLocked()

	if !validator {
		timeTrace.start("post ptx")
		fmt.Println("post ptx,", time.Now(), ptx.Hash().Hex())
		go te.ethereum.EventMux().Post(PtxPreEvent{ptx})
	}
	return ptx
}

func (te *TransactionExecutor) receiveTx() {
	//TODO: ugly implementation!!!
	for {
		select {
		case txObj := <-te.txSub.Chan():
			//received one raw tx
			if txObj == nil {
				// fmt.Println("nil txObj")
				break
			}
			event := txObj.Data.(TxPreEvent)
			// fmt.Println("ptx pool add tx hash", event.Tx.Hash().Hex())
			//fmt.Println("recieve raw tx", event.Tx.Nonce())
			var err error
			if event.Local {
				err = te.txPool.AddLocal(event.Tx)
			} else {
				err = te.txPool.AddRemote(event.Tx)
			}
			if err != nil {
				fmt.Println("add tx error", err)
			}
			te.requestDispatchTx()
		case <-te.quit:
			return
		}
	}
}

func (te *TransactionExecutor) dispatchLoop() {
	//TODO: ugly implementation!!!
	go te.receiveTx()
	for {
		select {
		case wg := <-te.stopDispatchChain:
			wg.Done()
		case <-te.dispatchTxChain:
			te.dispatchTx()
		case data := <-te.dispatchDagCh:
			fmt.Println("process dag")
			te.cacheDagTxs(data.ptx)
			te.dispatchTxDag(data.ptx.Dag())
			te.ResumeThread()
			te.waitForTxExecution() // make sure daq tx running over.
			te.processOneCycle(true)
			data.wg.Done()
		case <-te.quit:
			return
		}
	}
}

func (te *TransactionExecutor) cacheDagTxs(ptx *ParalleledTransaction) {
	for _, txBytes := range ptx.data.Txs {
		tx, err := decodeTx(txBytes)
		if err == nil {
			te.txCache[tx.Hash()] = tx
		}
	}
}

func (te *TransactionExecutor) dispatchTxDag(txDag *Dag) {
	parallelNodes := txDag.Serialize()
	for _, nodes := range parallelNodes {
		txs := []*ethTypes.Transaction{}
		for _, node := range nodes {
			tx, _ := te.txCache[node]
			if tx == nil {
				tx = te.txPool.Get(node)
			}
			if tx == nil {
				fmt.Printf("ERROR: Can not find Tx with hash code", node.Hex())
				continue
			}
			txs = append(txs, tx)
		}

		//TODO: better thread posting
		for _, threadContext := range te.threads {
			if threadContext.pendingTxSize() == 0 {
				// TODO:check from and to address
				threadContext.queueTxs(txs)
				break
			}
		}
	}
}

func (te *TransactionExecutor) waitForTxExecution() {
	// check if all threads are done.
	// TODO: timeout/kill for waiting
	wg := &sync.WaitGroup{}
	for _, thread := range te.threads {
		wg.Add(1)
		thread.addEmptyWait(wg)
	}
	wg.Wait()
	fmt.Println("waitForTxExecution done")
}

func (te *TransactionExecutor) filterTxs(txs map[common.Address]ethTypes.Transactions) map[common.Address]ethTypes.Transactions {
	realTxs := make(map[common.Address]ethTypes.Transactions)
	for adr, txList := range txs {
		var tmptxs ethTypes.Transactions
		for _, tx := range txList {
			skipped := false
			if _, ok := te.executingTxs[tx.Hash()]; ok {
				skipped = true
			}
			if !skipped {
				if _, ok := te.executedTxs[tx.Hash()]; ok {
					skipped = true
				}
			}
			if !skipped {
				tmptxs = append(tmptxs, tx)
			}
		}
		if len(tmptxs) > 0 {
			realTxs[adr] = tmptxs
		}
	}
	return realTxs
}

func (te *TransactionExecutor) dispatchTx() []*ethTypes.Transaction {
	//TODO: optimize
	te.lock("dispatchTx")
	defer te.unlock("dispatchTx")
	if te.dispatchPausing {
		//fmt.Println("pausing")
		return nil
	}
	if te.txPool == nil {
		fmt.Println("nil txpool")
		return nil
	}
	txs, _ := te.txPool.Pending()
	if len(txs) == 0 {
		return nil
	}

	if WAIT_MIN_TX && firstDispatch && len(txs) < MIN_TX_COUNT {
		return nil
	}
	if firstDispatch {
		te.resetCycleTickerLocked()
		timeTrace.reset()
		timeTrace.start("blockTime")
	}
	firstDispatch = false
	timeTrace.start("dispatchTx")
	defer timeTrace.endWithPrint("dispatchTx")

	//fmt.Println("dispatch pending txs:", len(txs), time.Now())

	realTxs := te.filterTxs(txs)
	//fmt.Println("dispatch real pending txs:", len(realTxs))
	newTxs := ethTypes.NewTransactionsByPriceAndNonce(realTxs)
	for {
		tx := newTxs.Peek()
		if tx == nil {
			break
		}

		// Check whether the tx is replay protected. If we're not in the EIP155 hf
		// phase, start ignoring the sender until we do.
		if tx.Protected() && !te.config.IsEIP155(te.header.Number) {
			newTxs.Pop()
			continue
		}

		from, _ := tx.From(te.txPool.Signer(), false)
		to := *tx.To()
		if thread, ok := te.executingTxsInfo[from]; !TEST_CONTRACT && ok {
			thread.queueTx(tx)
		} else if thread, ok := te.executingTxsInfo[to]; !TEST_CONTRACT && ok {
			thread.queueTx(tx)
		} else {
			thread := te.chooseThread()
			if thread == nil {
				break
			}
			thread.queueTx(tx)
			te.executingTxsInfo[from] = thread
			te.executingTxsInfo[to] = thread
		}

		newTxs.Shift()
		te.executingTxs[tx.Hash()] = tx
	}

	return nil
}

func (te *TransactionExecutor) chooseThread() *threadContext {
	minLoad := 1000000000
	var selectedThread *threadContext
	//choosedIndex := 0
	for _, threadContext := range te.threads {
		len := threadContext.pendingTxSize()
		if len > THREAD_MAX_PENDING_TX_SIZE {
			continue
		} else if len < minLoad {
			selectedThread = threadContext
			minLoad = len
			//choosedIndex = index
		}
	}
	//fmt.Println("==========choosed thread========", choosedIndex)
	return selectedThread
}

func (te *TransactionExecutor) generatePtx(root common.Hash, database state.Database) (*ParalleledTransaction, *state.StateDB, [][]*ExecutedTransaction) {
	//TODO:Optimize
	timeTrace.start("generatePtx")
	defer timeTrace.end("generatePtx")
	fmt.Println("generatePtx")
	maxExecutedTxSize := 0
	var allTxs [][]*ExecutedTransaction
	var selectedTxs []*ExecutedTransaction
	mainThreadIndex := -1
	for index, threadContext := range te.threads {
		txs := threadContext.dequeueExecutedTxs()
		if len(txs) > maxExecutedTxSize {
			maxExecutedTxSize = len(txs)
			selectedTxs = txs
			mainThreadIndex = index
		}
	}
	if selectedTxs == nil || len(selectedTxs) <= 0 {
		fmt.Println("no executed tx")
		return nil, nil, nil
	}

	fmt.Println("selected main thread:", mainThreadIndex)

	start := time.Now()
	var tmp *state.StateDB
	if OPT_REUSE_STATE {
		//Notice:Reuse state needs to notice Nonce issue
		threadContext := te.threads[mainThreadIndex]
		threadContext.pauseAndWait()
		selectedTxs = threadContext.dequeueExecutedTxs()
		tmp = threadContext.getState()
	} else {
		tmp, _ = state.New(root, database)
		te.applyTxsState(tmp, selectedTxs)
	}
	start1 := time.Now()
	state := tmp
	allTxs = append(allTxs, selectedTxs)
	for index, threadContext := range te.threads {
		selectedTxs = nil
		if index == mainThreadIndex {
			continue
		}
		etxs := threadContext.getExecutedTxs()
		fmt.Println("executed txs len:", len(etxs), " thread:", index)
		for _, etx := range etxs {
			passed := !te.checkStateConflict(state, etx)
			// fmt.Println("selected tx nonce", etx.tx.Hash().Hex(), " thread:", index, passed)
			if passed {
				selectedTxs = append(selectedTxs, etx)
				te.applyTxState(state, etx)
			}
		}
		if selectedTxs != nil && len(selectedTxs) > 0 {
			allTxs = append(allTxs, selectedTxs)
		}
	}

	if allTxs == nil || len(allTxs) <= 0 {
		fmt.Println("no executed tx")
		return nil, nil, nil
	}
	fmt.Println("generatePtx cost,", time.Now().Sub(start), time.Now().Sub(start1))

	ptx := &ParalleledTransaction{}
	ptx.fillTxs(allTxs)
	//TODO:Produce ptx.dag
	return ptx, state, allTxs
}

func (te *TransactionExecutor) checkStateConflict(state *state.StateDB, etx *ExecutedTransaction) bool {
	if etx == nil {
		return true
	}
	loadeds := etx.tracer.LoadedValues()
	for addr, storage := range loadeds {
		for k, v := range storage {
			sv := state.GetState(addr, k)
			if sv != v {
				return true
			}
		}
	}
	return false
	//TODO:createContract data and balance state
}

func (te *TransactionExecutor) requestDispatchTx() {
	select {
	case te.dispatchTxChain <- struct{}{}:
	default:
	}
}

func (te *TransactionExecutor) DeliverTx(ptx *ParalleledTransaction) bool {
	te.lock("DeliverTx")
	defer te.unlock("DeliverTx")
	if te.firstCycleCtx == nil {
		fmt.Println("DeliverTx firstCycleCtx nil")
		return false
	}
	fmt.Println("ptx length:", len(ptx.data.TxIds), ptx.Hash().Hex(), time.Now())
	// for _, txid := range ptx.data.TxIds {
	// 	fmt.Println("ptx selected:", txid.Hex())
	// }
	if te.selectedCycleCtx == nil {
		fmt.Println("ptx hash:", ptx.Hash().Hex())
		fmt.Println("cycle hash:", te.firstCycleCtx.ptx.Hash().Hex())
		if ptx.Hash() == te.firstCycleCtx.ptx.Hash() {
			te.selectedCycleCtx = te.firstCycleCtx
			return true
		} else {
			fmt.Println("DeliverTx unmatched first cycle ptx hash,", ptx.Hash().Hex(), te.firstCycleCtx.ptx.Hash().Hex())
			return false
		}
	} else if te.selectedCycleCtx.next.ptx.Hash() == ptx.Hash() {
		te.selectedCycleCtx = te.selectedCycleCtx.next
		return true
	} else {
		fmt.Println("DeliverTx unmatched selected cycle ptx hash,", ptx.Hash().Hex(), te.selectedCycleCtx.next.ptx.Hash().Hex())
		return false
	}
}

func (te *TransactionExecutor) beginBlock() {
	fmt.Println("begin block", time.Now())
	timeTrace.end("post ptx")
	timeTrace.start("handleBlock")
	te.stop()
	if te.IsValidator() {
		te.resetState()
	}
	startBeginBlock = true
}

func (te *TransactionExecutor) stop() {
	te.lock("stop step1")
	te.stopped = true
	fmt.Println("te stop")
	wg := &sync.WaitGroup{}
	wg.Add(2)
	te.StopCycle(wg)
	te.StopDispatch(wg)
	te.unlock("stop step1")
	//wait cycle and dispatch thread stop
	wg.Wait()
	fmt.Println("stop cycle dispatch done")

	te.lock("stop step2")
	for _, thread := range te.threads {
		wg.Add(1)
		thread.pauseAndWaitWg(wg)
	}
	te.unlock("stop step2")
	wg.Wait()
	for _, thread := range te.threads {
		thread.invalidTxs()
	}
	fmt.Println("te stop done")
}

func (te *TransactionExecutor) Pause() {
	fmt.Println("te pause")
	te.PauseCycle()
	te.PauseDispatch()
	te.PauseThread()
}

func (te *TransactionExecutor) Resume() {
	fmt.Println("te resume")
	if te.stopped {
		return
	}
	te.ResumeCycle()
	te.ResumeDispatch()
	te.ResumeThread()
}

func (te *TransactionExecutor) PauseThread() {
	for _, thread := range te.threads {
		thread.Pause()
	}
}

func (te *TransactionExecutor) ResumeThread() {
	for _, thread := range te.threads {
		thread.Resume()
	}
}

func (te *TransactionExecutor) start() {
	te.lock("start")
	defer te.unlock("start")
	te.startLocked()
}

func (te *TransactionExecutor) startLocked() {
	fmt.Println("te start")

	te.stopped = false
	te.Resume()
}

func (te *TransactionExecutor) StopCycle(wg *sync.WaitGroup) {
	fmt.Println("StopCycle")
	select {
	case oldWg := <-te.stopCycleChain:
		oldWg.Done()
	default:
	}
	te.PauseCycle()
	te.stopCycleChain <- wg
}

func (te *TransactionExecutor) PauseCycle() {
	fmt.Println("Pause Cycle")
	te.cyclePausing = true
}

func (te *TransactionExecutor) ResumeCycle() {
	fmt.Println("Resume Cycle")
	if te.stopped {
		return
	}
	te.cyclePausing = false
}

func (te *TransactionExecutor) StartCycle() {
	fmt.Println("StartCycle")
	// te.resetCycleTicker()
	te.ResumeCycle()
}

func (te *TransactionExecutor) StopDispatch(wg *sync.WaitGroup) {
	fmt.Println("StopDispatch")
	select {
	case oldWg := <-te.stopDispatchChain:
		oldWg.Done()
	default:
	}
	te.PauseDispatch()
	te.stopDispatchChain <- wg
}

func (te *TransactionExecutor) PauseDispatch() {
	fmt.Println("Pause Dispatch")
	te.dispatchPausing = true
}

func (te *TransactionExecutor) ResumeDispatch() {
	fmt.Println("Resume Dispatch")
	if te.stopped {
		return
	}
	te.dispatchPausing = false
	te.requestDispatchTx()
}

func (te *TransactionExecutor) StartDispatch() {
	fmt.Println("StartDispatch")
	te.ResumeDispatch()
}

func (te *TransactionExecutor) commitState() *state.StateDB {
	startBeginBlock = false
	te.lock("commitState")
	defer te.unlock("commitState")
	fmt.Println("te commitState", time.Now())
	defer fmt.Println("te commitState done", time.Now())
	var newWs *state.StateDB
	if te.selectedCycleCtx != nil {
		newWs = te.selectedCycleCtx.ws.Copy()
	} else {
		newWs = te.state.Copy()
	}
	// from := common.HexToAddress("0xbc44a0962a82f89d660f5ccfa4fc1a51cce696ca")
	// fmt.Println("11nonce:", newWs.GetNonce(from))
	// if te.IsValidator() {
	// 	te.startLocked()
	// }
	return newWs
}

func (te *TransactionExecutor) makeCurrent(ethereum *eth.Ethereum, ethConfig *eth.Config, header *ethTypes.Header, parent *ethTypes.Block, state *state.StateDB) error {
	te.lock("makeCurrent")
	defer te.unlock("makeCurrent")
	fmt.Println("make current", time.Now())

	te.ethereum = ethereum
	te.ethConfig = ethConfig
	te.header = header
	te.parent = parent
	te.state = state.Copy()
	//from := common.HexToAddress("0x257aab3f139bd48d042a03817fe9b8bb9d2d163f")
	//fmt.Println("make current nonce:", te.state.GetNonce(from))
	ret := te.resetStateLocked()
	//TODO:Workaround to call ChainHeadEvent synchronizing
	timeTrace.start("onChainHead")
	te.txPool.OnChainHeadEvent()
	timeTrace.endWithPrint("onChainHead")
	// go te.eventMux.Post(core.ChainHeadEvent{})

	te.startLocked()
	// te.Resume()

	timeTrace.end("handleBlock")
	timeTrace.end("blockTime")
	timeTrace.printAll()
	timeTrace.start("blockTime")
	fmt.Println("new block", time.Now())
	return ret
}

func (te *TransactionExecutor) resetState() error {
	te.lock("resetState")
	defer te.unlock("resetState")
	return te.resetStateLocked()
}

func (te *TransactionExecutor) resetStateLocked() error {
	te.txCache = make(map[common.Hash]*ethTypes.Transaction)
	te.executedTxs = make(map[common.Hash]*ExecutedTransaction)
	te.executingTxsInfo = make(map[common.Address]*threadContext)
	te.currentCycleCtx = nil
	te.selectedCycleCtx = nil
	te.firstCycleCtx = nil
	ret := te.updateStateLocked()
	te.resetCycleTickerLocked()
	return ret
}

func (te *TransactionExecutor) updateState() error {
	te.lock("updateState")
	defer te.unlock("updateState")
	return te.updateStateLocked()
}

func (te *TransactionExecutor) updateStateLocked() error {
	timeTrace.start("updateStateLocked")
	defer timeTrace.end("updateStateLocked")
	fmt.Println("te update state")
	te.executingTxs = make(map[common.Hash]*ethTypes.Transaction)
	var preState *state.StateDB
	//TODO: when currentCycleCtx become nil?
	if te.currentCycleCtx != nil {
		preState = te.currentCycleCtx.ws
	} else {
		preState = te.state
	}
	//TODO:Optimize
	root, _ := preState.CommitTo(te.ethereum.ChainDb(), false)
	//root := preState.IntermediateRoot(false)

	tmp, err := state.New(root, preState.GetDataBase())

	if err != nil {
		fmt.Println("new statedb error", err)
		return nil
	}
	te.currentState = tmp
	// te.currentState = preState
	te.currentRoot = root
	//txpool must initiliaz after currentState initialize
	if te.txPool == nil {
		te.eventMux = new(event.TypeMux)
		te.txPool = core.NewTxPool(te.ethConfig.TxPool, te.config, te.eventMux, te.State, te.GasLimit)
	}

	for _, thread := range te.threads {
		state, err := state.New(root, preState.GetDataBase())
		if err != nil {
			fmt.Println("new statedb error", err)
			break
		}

		thread.UpdateThreadState(te.ethereum, te.ethConfig, te.header, te.parent, state)
	}
	te.requestDispatchTx()
	return nil
}

type threadContext struct {
	index     int
	ethereum  *eth.Ethereum
	ethConfig *eth.Config

	executedTxs []*ExecutedTransaction

	requestTxChain chan struct{}
	executingTxs   *list.List
	quit           chan struct{}
	waitTxChan     chan struct{}
	waitEmptyChan  chan *sync.WaitGroup

	// tell all pushed tx are done.
	fenceChan chan *sync.WaitGroup

	state threadState

	pausing bool

	//TODO:really need?
	mtx sync.Mutex
}

func (tc *threadContext) UpdateThreadState(ethereum *eth.Ethereum, ethConfig *eth.Config, header *ethTypes.Header, parent *ethTypes.Block, state *state.StateDB) error {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	tc.ethereum = ethereum
	tc.ethConfig = ethConfig
	return tc.updateThreadStateLocked(header, parent, state)
}

func (tc *threadContext) updateThreadStateLocked(header *ethTypes.Header, parent *ethTypes.Block, state *state.StateDB) error {
	tc.executedTxs = nil
	tc.executingTxs = &list.List{}
	tc.state = threadState{
		index:        tc.index,
		header:       header,
		parent:       parent,
		state:        state,
		txIndex:      0,
		totalUsedGas: big.NewInt(0),
		gp:           new(core.GasPool).AddGas(header.GasLimit),
	}
	return nil
}

func (tc *threadContext) executeTx(blockchain *core.BlockChain, config *eth.Config,
	chainConfig *params.ChainConfig, blockHash common.Hash,
	tx *ethTypes.Transaction) (*ExecutedTransaction, error) {
	return tc.state.executeTx(blockchain, config, chainConfig, blockHash, tx)
}

func (tc *threadContext) notifyTx() {
	select {
	case tc.waitTxChan <- struct{}{}:
		//fmt.Println("notify new tx")
	default:
	}
}

func (tc *threadContext) requestTx() {
	select {
	case tc.requestTxChain <- struct{}{}:
		//fmt.Println("request new tx")
	default:
	}
}

func (tc *threadContext) addEmptyWait(wg *sync.WaitGroup) {
	fmt.Println("addEmptyWait")
	tc.mtx.Lock()
	defer tc.mtx.Unlock()

	// if tc.executingTxs.Len() == 0 {
	// 	wg.Done()
	// 	return
	// }
	select {
	case oldWg := <-tc.waitEmptyChan:
		oldWg.Done()
	default:
	}
	tc.notifyTx()
	tc.waitEmptyChan <- wg
}

func (tc *threadContext) waitTx() {
	select {
	case oldWg := <-tc.waitEmptyChan:
		oldWg.Done()
	default:
	}
	tc.requestTx()
	//fmt.Println("wait tx")
	<-tc.waitTxChan
	//fmt.Println("wait tx done")
}

func (tc *threadContext) dequeueTx() *ethTypes.Transaction {
	str := fmt.Sprintf("dequeueTx%d", tc.index)
	timeTrace.start(str)
	defer timeTrace.end(str)
	tc.mtx.Lock()
	defer tc.mtx.Unlock()

	txElem := tc.executingTxs.Front()
	//fmt.Println("tc dequeue tx,", tc.index)
	if txElem != nil {
		value := tc.executingTxs.Remove(txElem)
		tx := value.(*ethTypes.Transaction)
		return tx
	} else {
		return nil
	}
}

func (tc *threadContext) pauseAndWait() {
	wg := &sync.WaitGroup{}
	wg.Add(1)
	tc.pauseAndWaitWg(wg)
	wg.Wait()
	fmt.Println("wait invalid done")
}

func (tc *threadContext) pauseAndWaitWg(wg *sync.WaitGroup) {
	select {
	case oldWg := <-tc.fenceChan:
		fmt.Println("Invalid existed data")
		oldWg.Done()
	default:
	}
	tc.Pause()
	tc.fenceChan <- wg
	tc.notifyTx()
}

func (tc *threadContext) invalidTxs() {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	tc.executedTxs = nil
	tc.executingTxs = &list.List{}
}

func (tc *threadContext) queueTx(tx *ethTypes.Transaction) {
	timeTrace.start("queueTx")
	defer timeTrace.end("queueTx")
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	tc.executingTxs.PushBack(tx)
	// fmt.Println("queue one tx to thread,", tc.index, tx.Hash().Hex())
	tc.notifyTx()
}

func (tc *threadContext) queueTxs(txs []*ethTypes.Transaction) {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	for _, tx := range txs {
		tc.executingTxs.PushBack(tx)
	}
	tc.notifyTx()
}

func (tc *threadContext) exit() {
	tc.quit <- struct{}{}
}

func (tc *threadContext) pendingTxSize() int {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	return tc.executingTxs.Len()
}

func (tc *threadContext) getState() *state.StateDB {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	return tc.state.state
}

func (tc *threadContext) getExecutedTxs() []*ExecutedTransaction {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	return tc.executedTxs
}

func (tc *threadContext) dequeueExecutedTxs() []*ExecutedTransaction {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	ret := tc.executedTxs
	// tc.executedTxs = nil
	return ret
}

func (tc *threadContext) queueExecutedTx(etx *ExecutedTransaction) {
	tc.mtx.Lock()
	defer tc.mtx.Unlock()
	tc.executedTxs = append(tc.executedTxs, etx)
}

func (tc *threadContext) Pause() {
	tc.pausing = true
}

func (tc *threadContext) Resume() {
	tc.pausing = false
	tc.notifyTx()
}

func (tc *threadContext) loop() error {
	for {
		select {
		case <-tc.quit:
			fmt.Println("quit")
			return nil
		case wg := <-tc.fenceChan:
			fmt.Println("-----handle invalid----")
			wg.Done()
		default:
		}
		if tc.pausing {
			tc.waitTx()
			continue
		}
		tx := tc.dequeueTx()
		if tx != nil {
			blockchain := tc.ethereum.BlockChain()
			chainConfig := tc.ethereum.ApiBackend.ChainConfig()
			blockHash := common.Hash{}
			//fmt.Println("executing tx", tx.Hash().Hex())
			if executedTx, err := tc.executeTx(blockchain, tc.ethConfig, chainConfig, blockHash, tx); err == nil {
				//fmt.Println("one executed tx", tx.Hash().Hex())
				tc.queueExecutedTx(executedTx)
			} else {
				//TODO: error handling?
			}
		} else {
			//empty transaction
			tc.waitTx()
		}
	}
	return nil
}

type threadState struct {
	//global shared object with all threadState in same workState
	index  int
	header *ethTypes.Header
	parent *ethTypes.Block
	state  *state.StateDB
	gp     *core.GasPool

	txIndex int

	totalUsedGas *big.Int
}

// Runs ApplyTransaction against the ethereum blockchain, fetches any logs,
// and appends the tx, receipt, and logs.
func (ts *threadState) executeTx(blockchain *core.BlockChain, config *eth.Config,
	chainConfig *params.ChainConfig, blockHash common.Hash,
	tx *ethTypes.Transaction) (*ExecutedTransaction, error) {
	if !isEthTx(tx) {
		return &ExecutedTransaction{tx: tx, receipt: nil, tracer: nil}, nil
	}
	str := fmt.Sprintf("executeTx%d", ts.index)
	timeTrace.start(str)
	defer timeTrace.end(str)
	//new tracer for this transaction
	hash := tx.Hash()
	tracer := NewContractTrace(&hash)

	//just thread txIndex, wait tx selector to fill log.index using global tx_index
	// ts.state.Prepare(tx.Hash(), blockHash, ts.txIndex)
	ts.state.SetStateTrace(tracer)
	// to := common.HexToAddress("0x8888abe59640800604a2fdb704c7ba6d00087e9b")
	// fmt.Println("execute before", ts.state.GetBalance(to))
	state := ts.state
	state.Prepare(tx.Hash(), blockHash, ts.txIndex)
	// state.SetBalance(to, big.NewInt(12345678));
	receipt, _, err := ApplyTransaction(
		chainConfig,
		blockchain,
		nil, // defaults to address of the author of the header
		ts.gp,
		state,
		ts.header,
		tx,
		//only this thread total used gas, wait tx selector to fill receipt.CumulativeGasUsed using global totalGasUsed
		ts.totalUsedGas,
		// vm.Config{EnablePreimageRecording: config.EnablePreimageRecording, Debug: true, Tracer: tracer},
		vm.Config{EnablePreimageRecording: config.EnablePreimageRecording},
	)
	if err != nil {
		return nil, err
	}

	// fmt.Println("execute after:", ts.state.GetBalance(to))
	// fmt.Println("execute after1:", state.GetBalance(to))
	// state2, _ := blockchain.State()
	// fmt.Println("execute after global:", state2.GetBalance(to))
	// logs := ts.state.GetLogs(tx.Hash())

	// ts.txIndex++

	// The slices are allocated in updateHeaderWithTimeInfo
	// executedTx := &ExecutedTransaction{tx: tx, receipt: receipt, logs: logs, tracer: tracer}
	executedTx := &ExecutedTransaction{tx: tx, receipt: receipt, tracer: tracer}

	return executedTx, nil
}
