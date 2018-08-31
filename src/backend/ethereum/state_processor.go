package ethereum

import (
	"math/big"

	// "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	// "github.com/ethereum/go-ethereum/crypto"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// StateProcessor is a basic Processor, which takes care of transitioning
// state from one point to another.
//
// StateProcessor implements Processor.
type StateProcessor struct {
	config *params.ChainConfig // Chain configuration options
	bc     *core.BlockChain    // Canonical block chain
	engine consensus.Engine    // Consensus engine used for block rewards
	state  *state.StateDB

	receipts ethTypes.Receipts
	logs     []*ethTypes.Log
}

// NewStateProcessor initialises a new StateProcessor.
func NewStateProcessor(config *params.ChainConfig, bc *core.BlockChain, engine consensus.Engine) *StateProcessor {
	return &StateProcessor{
		config: config,
		bc:     bc,
		engine: engine,
	}
}

func (p *StateProcessor) Prepare(state *state.StateDB, receipts ethTypes.Receipts, logs []*ethTypes.Log) {
	p.state = state
	p.receipts = receipts
	p.logs = logs
}

// Process processes the state changes according to the Ethereum rules by running
// the transaction messages using the statedb and applying any rewards to both
// the processor (coinbase) and any included uncles.
//
// Process returns the receipts and logs accumulated during the process and
// returns the amount of gas that was used in the process. If any of the
// transactions failed to execute due to insufficient gas it will return an error.
func (p *StateProcessor) Process(block *types.Block, statedb *state.StateDB, cfg vm.Config) (types.Receipts, []*types.Log, *big.Int, error) {
	// var (
	// 	receipts     types.Receipts
	// 	totalUsedGas = big.NewInt(0)
	// 	header       = block.Header()
	// 	allLogs      []*types.Log
	// 	gp           = new(GasPool).AddGas(block.GasLimit())
	// )
	// // Mutate the the block and state according to any hard-fork specs
	// if p.config.DAOForkSupport && p.config.DAOForkBlock != nil && p.config.DAOForkBlock.Cmp(block.Number()) == 0 {
	// 	misc.ApplyDAOHardFork(statedb)
	// }
	// // Iterate over and process the individual transactions
	// for i, tx := range block.Transactions() {
	// 	statedb.Prepare(tx.Hash(), block.Hash(), i)
	// 	receipt, _, err := ApplyTransaction(p.config, p.bc, nil, gp, statedb, header, tx, totalUsedGas, cfg)
	// 	if err != nil {
	// 		return nil, nil, nil, err
	// 	}
	// 	receipts = append(receipts, receipt)
	// 	allLogs = append(allLogs, receipt.Logs...)
	// }

	// Finalize the block, applying any consensus engine specific extras (e.g. block rewards)
	p.engine.Finalize(p.bc, block.Header(), p.state, block.Transactions(), block.Uncles(), p.receipts)

	return p.receipts, p.logs, block.Header().GasUsed, nil
}

func ApplyTransaction(config *params.ChainConfig, bc *core.BlockChain, author *common.Address, gp *core.GasPool, statedb *state.StateDB, header *types.Header, tx *types.Transaction, usedGas *big.Int, cfg vm.Config) (*types.Receipt, *big.Int, error) {
	msg, err := tx.AsMessage(types.MakeSigner(config, header.Number))
	if err != nil {
		return nil, nil, err
	}
	// Create a new context to be used in the EVM environment
	context := core.NewEVMContext(msg, header, bc, author)
	// Create a new environment which holds all relevant information
	// about the transaction and calling mechanisms.
	vmenv := vm.NewEVM(context, statedb, config, cfg)
	// Apply the transaction to the current state (included in the env)
	_, gas, err := core.ApplyMessage(vmenv, msg, gp)
	if err != nil {
		return nil, nil, err
	}

	// Update the state with pending changes
	usedGas.Add(usedGas, gas)
	// Create a new receipt for the transaction, storing the intermediate root and gas used by the tx
	// based on the eip phase, we're passing wether the root touch-delete accounts.

	//TODO:Optimize
	// root := statedb.IntermediateRoot(config.IsEIP158(header.Number))
	receipt := types.NewReceipt([]byte{}, usedGas)
	receipt.TxHash = tx.Hash()
	receipt.GasUsed = new(big.Int).Set(gas)
	// if the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		receipt.ContractAddress = crypto.CreateAddress(vmenv.Context.Origin, tx.Nonce())
	}

	// Set the receipt logs and create a bloom for filtering
	receipt.Logs = statedb.GetLogs(tx.Hash())
	receipt.Bloom = types.CreateBloom(types.Receipts{receipt})

	return receipt, gas, err
}
