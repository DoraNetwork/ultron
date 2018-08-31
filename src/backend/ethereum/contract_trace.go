// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethereum

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/rlp"
)

// ContractTrace is an EVM state logger and implements Tracer.
//
// ContractTrace can capture state based on the given Log configuration and also keeps
// a track record of modified storage which is used in reporting snapshots of the
// contract their storage.

type ContractTrace struct {
	state.StateTrace
	loadedGlobalValues map[common.Address]EvmGlobalVariables
	loadedValues       map[common.Address]vm.Storage
	changedValues      map[common.Address]vm.Storage

	loadedBalances   map[common.Address]*big.Int
	changedBalances  map[common.Address]*big.Int
	createdContracts map[common.Address][]byte

	output      []byte
	err         error
	callAdr     common.Address
	contractAdr common.Address
	tag         interface{}
	duration    time.Duration
	gasUsed     uint64
}

type EvmGlobalVariables map[vm.OpCode][]byte

// NewContractTrace returns a new logger
func NewContractTrace(tag interface{}) *ContractTrace {
	logger := &ContractTrace{
		loadedValues:       make(map[common.Address]vm.Storage),
		loadedGlobalValues: make(map[common.Address]EvmGlobalVariables),
		changedValues:      make(map[common.Address]vm.Storage),
		loadedBalances:     make(map[common.Address]*big.Int),
		changedBalances:    make(map[common.Address]*big.Int),
		createdContracts:   make(map[common.Address][]byte),
	}
	if tag != nil {
		logger.tag = tag
	}
	return logger
}

func (l *ContractTrace) OnSetCode(addr common.Address, code []byte) {
	// fmt.Println("OnSetCode", addr.Hex())
	l.createdContracts[addr] = code
}

func (l *ContractTrace) OnAddBalance(addr common.Address, balance *big.Int, amount *big.Int) {
	// fmt.Println("OnAddBalance", addr.Hex(), balance, amount)

	if _, ok := l.loadedBalances[addr]; !ok {
		tmp := new(big.Int)
		tmp.Set(balance)
		l.loadedBalances[addr] = tmp
	}
	tmp := new(big.Int)
	tmp.Set(balance)
	tmp.Add(tmp, amount)
	l.changedBalances[addr] = tmp
}

// SubBalance subtracts amount from the account associated with addr
func (l *ContractTrace) OnSubBalance(addr common.Address, balance *big.Int, amount *big.Int) {
	// fmt.Println("OnSubBalance", addr.Hex(), balance, amount)
	if _, ok := l.loadedBalances[addr]; !ok {
		tmp := new(big.Int)
		tmp.Set(balance)
		l.loadedBalances[addr] = tmp
	}
	tmp := new(big.Int)
	tmp.Set(balance)
	tmp.Sub(tmp, amount)
	l.changedBalances[addr] = tmp
}

func (l *ContractTrace) OnSetBalance(addr common.Address, balance *big.Int, amount *big.Int) {
	// fmt.Println("OnSetBalance", addr.Hex(), balance, amount)
	if _, ok := l.loadedBalances[addr]; !ok {
		tmp := new(big.Int)
		tmp.Set(balance)
		l.loadedBalances[addr] = tmp
	}
	tmp := new(big.Int)
	tmp.Set(amount)
	l.changedBalances[addr] = tmp
}

func (l *ContractTrace) OnGetBalance(addr common.Address, balance *big.Int) {
	// fmt.Println("OnGetBalance", addr.Hex(), balance)

	if _, ok := l.loadedBalances[addr]; !ok {
		tmp := new(big.Int)
		tmp.Set(balance)
		l.loadedBalances[addr] = tmp
	}
}

func (l *ContractTrace) OnGetState(addr common.Address, key common.Hash, value common.Hash) {
	if l.loadedValues[addr] == nil {
		l.loadedValues[addr] = make(vm.Storage)
	}
	if _, ok := l.loadedValues[addr][key]; !ok {
		//Only record the first read value for one key
		l.loadedValues[addr][key] = value
	}
}

func (l *ContractTrace) OnSetState(addr common.Address, key common.Hash, value common.Hash) {
	if l.changedValues[addr] == nil {
		l.changedValues[addr] = make(vm.Storage)
	}
	l.changedValues[addr][key] = value
}

func (l *ContractTrace) CaptureStart(from common.Address, to common.Address, create bool, input []byte, gas uint64, value *big.Int) error {
	//log.Info("capture start", "from", from, "to", to)
	l.callAdr = from
	l.contractAdr = to
	return nil
}

// CaptureState logs a new structured log message and pushes it out to the environment
//
// CaptureState also tracks SSTORE ops to track dirty values.
func (l *ContractTrace) CaptureState(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, vmstack *vm.Stack, contract *vm.Contract, depth int, err error) error {
	// initialise new changed values storage container for this contract
	// if not present.
	//TODO:needs sync with evm.stack
	var stack = Stack{data: vmstack.Data()}
	if l.changedValues[contract.Address()] == nil {
		l.changedValues[contract.Address()] = make(vm.Storage)
	}

	if l.loadedValues[contract.Address()] == nil {
		l.loadedValues[contract.Address()] = make(vm.Storage)
	}

	if l.loadedGlobalValues[contract.Address()] == nil {
		l.loadedGlobalValues[contract.Address()] = make(EvmGlobalVariables)
	}

	// capture SSTORE opcodes and determine the changed value and store
	// it in the local storage container.
	var value interface{}
	switch op {
	case vm.SSTORE:
		if stack.len() >= 2 {
			var address = common.BigToHash(stack.data[stack.len()-1])
			var value = common.BigToHash(stack.data[stack.len()-2])
			l.changedValues[contract.Address()][address] = value
		}
		break
	case vm.SLOAD:
		if stack.len() >= 1 {
			var address = common.BigToHash(stack.data[stack.len()-1])
			if _, ok := l.loadedValues[contract.Address()][address]; !ok {
				//Only record the first read value for one key
				var value = env.StateDB.GetState(contract.Address(), address)
				l.loadedValues[contract.Address()][address] = value
			}
		}
		break
	//blockHash also just access blockNumber
	case vm.BLOCKHASH:
	case vm.NUMBER:
		value = env.BlockNumber
	case vm.COINBASE:
		value = env.Coinbase
	case vm.TIMESTAMP:
		value = env.Time
	case vm.DIFFICULTY:
		value = env.Difficulty
	case vm.GASLIMIT:
		value = env.GasLimit
	case vm.GASPRICE:
		value = env.GasPrice
		l.loadedGlobalValues[contract.Address()][op], err = rlp.EncodeToBytes(value)
		if err != nil {
			delete(l.loadedGlobalValues[contract.Address()], op)
		}
	default:
	}
	return nil
}

func (l *ContractTrace) verifyContext(env *vm.EVM) bool {
	for contract, state := range l.loadedValues {
		log.Info("\t", "load contract", contract)
		for k, v := range state {
			var value = env.StateDB.GetState(contract, k)
			if value.Big() != v.Big() {
				return false
			}
		}
	}
	for contract, state := range l.loadedGlobalValues {
		log.Info("\t", "load gloabl variable contract", contract)
		for k, v := range state {
			var value interface{}
			switch k {
			//blockHash also just access blockNumber
			case vm.BLOCKHASH:
			case vm.NUMBER:
				value = env.BlockNumber
			case vm.COINBASE:
				value = env.Coinbase
			case vm.TIMESTAMP:
				value = env.Time
			case vm.DIFFICULTY:
				value = env.Difficulty
			case vm.GASLIMIT:
				value = env.GasLimit
			case vm.GASPRICE:
				value = env.GasPrice
				rlpValue, err := rlp.EncodeToBytes(value)
				local := new(big.Int)
				remote := new(big.Int)
				if err != nil || local.SetBytes(rlpValue) != remote.SetBytes(v) {
					return false
				}
			default:
			}
		}
	}
	return true
}

func (l *ContractTrace) CheckAndRunContract(env *vm.EVM) bool {
	if !l.verifyContext(env) {
		return false
	}
	for contract, state := range l.changedValues {
		for k, v := range state {
			env.StateDB.SetState(contract, k, v)
		}
	}
	return true
}

func (l *ContractTrace) CaptureFault(env *vm.EVM, pc uint64, op vm.OpCode, gas, cost uint64, memory *vm.Memory, stack *vm.Stack, contract *vm.Contract, depth int, err error) error {
	return nil
}

func (l *ContractTrace) CaptureEnd(output []byte, gasUsed uint64, t time.Duration) error {
	if gasUsed > 0 {
		//log.Info("Capture end", "cost", common.PrettyDuration(t), "gasUsed", gasUsed)
	}
	l.duration = t
	l.gasUsed = gasUsed
	l.output = output
	return nil
}

// ContractTrace returns the captured changes.
func (l *ContractTrace) LoadedValues() map[common.Address]vm.Storage  { return l.loadedValues }
func (l *ContractTrace) ChangedValues() map[common.Address]vm.Storage { return l.changedValues }
func (l *ContractTrace) ChangedBalances() map[common.Address]*big.Int { return l.changedBalances }
func (l *ContractTrace) CreatedContracts() map[common.Address][]byte  { return l.createdContracts }

// Error returns the VM error captured by the trace.
func (l *ContractTrace) Error() error { return l.err }

// Output returns the VM return value captured by the trace.
func (l *ContractTrace) Output() []byte { return l.output }

// Output returns the VM return value captured by the trace.
func (l *ContractTrace) Tag() interface{} { return l.tag }

func (l *ContractTrace) CallAddress() common.Address { return l.callAdr }

func (l *ContractTrace) ContractAddress() common.Address { return l.contractAdr }

func (l *ContractTrace) GasUsed() uint64 { return l.gasUsed }

func (l *ContractTrace) Duration() time.Duration { return l.duration }

func (l *ContractTrace) LogState() {
	log.Info("*******Contract log state******")
	for contract, state := range l.changedValues {
		log.Info("\t", "store contract", contract)
		for k, v := range state {
			log.Info("\t\t", "key", k, "value", v)
		}
	}
	for contract, state := range l.loadedValues {
		log.Info("\t", "load contract", contract)
		for k, v := range state {
			log.Info("\t\t", "key", k, "value", v)
		}
	}
	for contract, state := range l.loadedGlobalValues {
		log.Info("\t", "load gloabl variable contract", contract)
		for k, v := range state {
			log.Info("\t\t", "key", k, "value", v)
		}
	}
	log.Info("-------Contract log state-----")
}
