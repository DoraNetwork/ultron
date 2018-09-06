package backend

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/rpc"
	abciTypes "github.com/tendermint/abci/types"
	tmn "github.com/tendermint/tendermint/node"
	rpcClient "github.com/tendermint/tendermint/rpc/client"

	"github.com/dora/ultron/backend/ethereum"
	emtTypes "github.com/dora/ultron/backend/types"
)

//----------------------------------------------------------------------
// Backend manages the underlying ethereum state for storage and processing,
// and maintains the connection to Tendermint for forwarding txs

// Backend handles the chain database and VM
// #stable - 0.4.0
type Backend struct {
	// backing ethereum structures
	ethereum  *eth.Ethereum
	ethConfig *eth.Config

	// txBroadcastLoop subscription
	txSub  *event.TypeMuxSubscription
	ptxSub *event.TypeMuxSubscription

	// EthState
	es *ethereum.EthStateWrapper

	// client for forwarding txs to Tendermint over http
	client *rpcClient.HTTP
	// local client for in-proc app to execute the rpc functions without the overhead of http
	localClient *rpcClient.Local

	// ultron chain id
	chainID string

	// moved from txpool.pendingState
	managedState *state.ManagedState
}

// NewBackend creates a new Backend
// #stable - 0.4.0
func NewBackend(ctx *node.ServiceContext, ethConfig *eth.Config,
	client *rpcClient.HTTP) (*Backend, error) {

	// Create working ethereum state.
	es := ethereum.NewEthStateWrapper()

	// eth.New takes a ServiceContext for the EventMux, the AccountManager,
	// and some basic functions around the DataDir.
	ethereum, err := eth.New(ctx, ethConfig, es)
	if err != nil {
		return nil, err
	}

	es.SetConfig(ethereum, ethConfig)

	// send special event to go-ethereum to switch homestead=true.
	currentBlock := ethereum.BlockChain().CurrentBlock()
	ethereum.EventMux().Post(core.ChainHeadEvent{currentBlock}) // nolint: vet, errcheck

	// We don't need PoW/Uncle validation.
	ethereum.BlockChain().SetValidator(NullBlockProcessor{})

	ethBackend := &Backend{
		ethereum:  ethereum,
		ethConfig: ethConfig,
		es:        es,
		client:    client,
	}
	ethBackend.ResetState()
	return ethBackend, nil
}

func (b *Backend) ResetState() (*state.ManagedState, error) {
	currentState, err := b.Ethereum().BlockChain().State()
	if err != nil {
		return nil, err
	}
	b.managedState = state.ManageState(currentState)
	return b.managedState, nil
}

func (b *Backend) ManagedState() *state.ManagedState {
	return b.managedState
}

// Ethereum returns the underlying the ethereum object.
// #stable
func (b *Backend) Ethereum() *eth.Ethereum {
	return b.ethereum
}

// Config returns the eth.Config.
// #stable
func (b *Backend) Config() *eth.Config {
	return b.ethConfig
}

func (b *Backend) SetTMNode(tmNode *tmn.Node) {
	b.chainID = tmNode.GenesisDoc().ChainID
	b.localClient = rpcClient.NewLocal(tmNode)
	// uncomment this for TxPool broadcast tx to tendermint directly,
	// the TxPool must has SetTMClient method when uncomment this
	b.ethereum.TxPool().SetTMClient(b.localClient)
}

//----------------------------------------------------------------------
// Handle block processing

func (b *Backend) UpdateProposer() {
	if b.es == nil {
		return
	}
	res, _ := b.client.Validators(nil)
	if res != nil {
		b.es.UpdateProposer(res.IsProposer)
	}
}

func (b *Backend) CheckTx(tx *ethTypes.Transaction) abciTypes.ResponseCheckTx {
	return b.es.CheckTx(tx)
}

// DeliverTx appends a transaction to the current block
// #stable
func (b *Backend) DeliverTx(tx *ethTypes.Transaction) abciTypes.ResponseDeliverTx {
	return b.es.DeliverTx(tx)
}

func (b *Backend) DeliverPtx(ptx *ethereum.ParalleledTransaction) abciTypes.ResponseDeliverTx {
	return b.es.DeliverPtx(ptx)
}

// AccumulateRewards accumulates the rewards based on the given strategy
// #unstable
func (b *Backend) AccumulateRewards(strategy *emtTypes.Strategy) {
	b.es.AccumulateRewards(strategy)
}

// Commit finalises the current block
// #unstable
func (b *Backend) Commit(receiver common.Address) (common.Hash, error) {
	return b.es.Commit(receiver)
}

func (b *Backend) EndBlock() {
	b.es.EndBlock()
}

func (b *Backend) GetTotalUsedGasFee() *big.Int {
	return b.es.TotalUsedGasFee
}

// InitEthState initializes the EthState
// #unstable
func (b *Backend) InitEthState(receiver common.Address) error {
	return b.es.ResetWorkState(receiver)
}

// UpdateHeaderWithTimeInfo uses the tendermint header to update the ethereum header
// #unstable
func (b *Backend) UpdateHeaderWithTimeInfo(tmHeader *abciTypes.Header) {
	b.es.UpdateHeaderWithTimeInfo(b.ethereum.ApiBackend.ChainConfig(), uint64(tmHeader.Time),
		uint64(tmHeader.GetNumTxs()))
}

// GasLimit returns the maximum gas per block
// #unstable
func (b *Backend) GasLimit() big.Int {
	return b.es.GasLimit()
}

// called by ultron tx only in deliver_tx
func (b *Backend) AddNonce(addr common.Address) {
	b.es.AddNonce(addr)
}

//----------------------------------------------------------------------
// Implements: node.Service

// APIs returns the collection of RPC services the ethereum package offers.
// #stable - 0.4.0
func (b *Backend) APIs() []rpc.API {
	apis := b.Ethereum().APIs()

	retApis := []rpc.API{}
	for _, v := range apis {
		if v.Namespace == "net" {
			continue
		}
		if v.Namespace == "miner" {
			continue
		}
		if _, ok := v.Service.(*eth.PublicMinerAPI); ok {
			continue
		}
		retApis = append(retApis, v)
	}
	return retApis
}

// Start implements node.Service, starting all internal goroutines needed by the
// Ethereum protocol implementation.
// #stable
func (b *Backend) Start(_ *p2p.Server) error {
	go b.txBroadcastLoop()
	return nil
}

// Stop implements node.Service, terminating all internal goroutines used by the
// Ethereum protocol.
// #stable
func (b *Backend) Stop() error {
	b.txSub.Unsubscribe()
	b.ethereum.Stop() // nolint: errcheck
	return nil
}

// Protocols implements node.Service, returning all the currently configured
// network protocols to start.
// #stable
func (b *Backend) Protocols() []p2p.Protocol {
	return nil
}

//----------------------------------------------------------------------
// We need a block processor that just ignores PoW and uncles and so on

// NullBlockProcessor does not validate anything
// #unstable
type NullBlockProcessor struct{}

// ValidateBody does not validate anything
// #unstable
func (NullBlockProcessor) ValidateBody(*ethTypes.Block) error { return nil }

// ValidateState does not validate anything
// #unstable
func (NullBlockProcessor) ValidateState(block, parent *ethTypes.Block, state *state.StateDB,
	receipts ethTypes.Receipts, usedGas *big.Int) error {
	return nil
}
