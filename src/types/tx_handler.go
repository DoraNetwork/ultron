package types

import (
	"github.com/cosmos/cosmos-sdk"
	"github.com/cosmos/cosmos-sdk/state"
)

type TxHandler interface {
	InitState(key, value string, store state.SimpleDB) error
	CheckTx(ctx Context, store state.SimpleDB, tx sdk.Tx) (sdk.CheckResult, error) 
	DeliverTx(ctx Context, store state.SimpleDB, tx sdk.Tx) (sdk.DeliverResult, error)
}