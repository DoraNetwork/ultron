package app

import (
	"encoding/json"
	"fmt"
	"strings"
	"github.com/dora/ultron/types"
	"github.com/cosmos/cosmos-sdk"
	"github.com/cosmos/cosmos-sdk/errors"
	"github.com/cosmos/cosmos-sdk/state"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	abci "github.com/tendermint/abci/types"
)

type TxDispatcher struct {
	txHandlers map[string]types.TxHandler
}

func NewTxDispatcher() *TxDispatcher {
	return &TxDispatcher{
		txHandlers: make(map[string]types.TxHandler, 0),
	}
}

func (td *TxDispatcher) RegisterTxHandler(txType string, handler types.TxHandler) {
	if td.txHandlers[txType] != nil {
		fmt.Printf("ERROR: %s handler already registered", txType)
	} else {
		td.txHandlers[txType] = handler
	}
}

func (td *TxDispatcher) UnregisterTxHandler(txType string) {
	td.txHandlers[txType] = nil
}

func (td *TxDispatcher) InitState(module string, key, value string, store state.SimpleDB) error {
	handler := td.txHandlers[module]
	if handler != nil {
		return handler.InitState(key, value, store)
	} else {
		return errors.ErrUnknownModule(module)
	}
}

func (td *TxDispatcher) CheckTx(app *BaseApp, tx *ethTypes.Transaction) abci.ResponseCheckTx {
	ctx := types.NewContext(app.GetChainID(), app.WorkingHeight(), app.ethereum)

	currentState, from, nonce, resp := app.EthApp.basicValidate(tx)
	if resp.Code != abci.CodeTypeOK {
		return resp
	}
	ctx.WithSigners(from)

	var innerTx sdk.Tx
	if err := json.Unmarshal(tx.Data(), &innerTx); err != nil {
		return errors.CheckResult(err)
	}

	handler, err := td.getTxHandler(innerTx)
	if err != nil {
		return errors.CheckResult(err)
	}

	var res sdk.CheckResult
	if handler != nil {
		res, err = handler.CheckTx(ctx, app.Check(), innerTx)
		if err != nil {
			return errors.CheckResult(err)
		}
	}

	currentState.SetNonce(from, nonce + 1)

	return res.ToABCI()
}

func (td *TxDispatcher) DeliverTx(app *BaseApp, tx *ethTypes.Transaction) abci.ResponseDeliverTx {
	ctx := types.NewContext(app.GetChainID(), app.WorkingHeight(), app.ethereum)

	var innerTx sdk.Tx
	if err := json.Unmarshal(tx.Data(), &innerTx); err != nil {
		return errors.DeliverResult(err)
	}

	var signer ethTypes.Signer = ethTypes.FrontierSigner{}
	if tx.Protected() {
		signer = ethTypes.NewEIP155Signer(tx.ChainId())
	}

	from, err := ethTypes.Sender(signer, tx)
	if err != nil {
		return errors.DeliverResult(err)
	}
	ctx.WithSigners(from)

	handler, err := td.getTxHandler(innerTx)
	if err != nil {
		return errors.DeliverResult(err)
	}

	var res sdk.DeliverResult
	if handler != nil {
		res, err = handler.DeliverTx(ctx, app.Append(), innerTx)
		if err != nil {
			return errors.DeliverResult(err)
		}
	}

	app.EthApp.backend.AddNonce(from)

	return res.ToABCI()
}

func (td *TxDispatcher)getTxHandler(tx sdk.Tx) (types.TxHandler, error) {
	kind, err := tx.GetKind()
	if err != nil {
		return nil, err
	}

	name := strings.SplitN(kind, "/", 2)[0]
	return td.txHandlers[name], nil
}
