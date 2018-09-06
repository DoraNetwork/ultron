package app

import (
	"bytes"
	"encoding/json"

	"github.com/dora/ultron/backend/ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	abciTypes "github.com/tendermint/abci/types"
)

// format of query data
type jsonRequest struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id,omitempty"`
	Params []interface{}   `json:"params,omitempty"`
}

// rlp decode an etherum transaction
func decodeTx(txBytes []byte) (*types.Transaction, error) {
	tx := new(types.Transaction)
	rlpStream := rlp.NewStream(bytes.NewBuffer(txBytes), 0)
	if err := tx.DecodeRLP(rlpStream); err != nil {
		return nil, err
	}
	return tx, nil
}

// rlp decode an etherum transaction
func decodePtx(txBytes []byte) (*ethereum.ParalleledTransaction, error) {
	ptx := new(ethereum.ParalleledTransaction)
	rlpStream := rlp.NewStream(bytes.NewBuffer(txBytes), 0)
	if err := ptx.DecodeRLP(rlpStream); err != nil {
		return nil, err
	}
	return ptx, nil
}

//-------------------------------------------------------
// convenience methods for validators

// Receiver returns the receiving address based on the selected strategy
// #unstable
func (app *EthermintApplication) Receiver() common.Address {
	if app.strategy != nil {
		return app.strategy.Receiver()
	}
	return common.Address{}
}

// SetValidators sets new validators on the strategy
// #unstable
func (app *EthermintApplication) SetValidators(validators []*abciTypes.Validator) {
	if app.strategy != nil {
		app.strategy.SetValidators(validators)
	}
}

// GetUpdatedValidators returns an updated validator set from the strategy
// #unstable
func (app *EthermintApplication) GetUpdatedValidators() abciTypes.ResponseEndBlock {
	if app.strategy != nil {
		return abciTypes.ResponseEndBlock{ValidatorUpdates: app.strategy.GetUpdatedValidators()}
	}
	return abciTypes.ResponseEndBlock{}
}

// CollectTx invokes CollectTx on the strategy
// #unstable
func (app *EthermintApplication) CollectTx(tx *types.Transaction) {
	if app.strategy != nil {
		app.strategy.CollectTx(tx)
	}
}
