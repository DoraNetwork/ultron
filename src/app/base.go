package app

import (
	goerr "errors"
	"fmt"
	"math/big"

	"github.com/cosmos/cosmos-sdk"
	"github.com/cosmos/cosmos-sdk/errors"
	"github.com/dora/ultron/backend/ethereum"
	"github.com/dora/ultron/const"
	ultronTypes "github.com/dora/ultron/errors"
	"github.com/dora/ultron/modules/stake"
	"github.com/dora/ultron/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/eth"
	abci "github.com/tendermint/abci/types"
	tmTypes "github.com/tendermint/tendermint/types"
)

// BaseApp - The ABCI application
type BaseApp struct {
	*StoreApp
	EthApp              *EthermintApplication
	txDispatcher        *TxDispatcher
	checkedTx           map[common.Hash]*types.Transaction
	ethereum            *eth.Ethereum
	AbsentValidators    []int32
	ByzantineValidators []*abci.Evidence
	Random              *abci.VrfRandom
}

// BaseApp extends StoreApp, and dispatch tx to different modules via TxDispatcher
func NewBaseApp(store *StoreApp, ethApp *EthermintApplication, ethereum *eth.Ethereum) (*BaseApp, error) {
	app := &BaseApp{
		StoreApp:     store,
		EthApp:       ethApp,
		txDispatcher: NewTxDispatcher(),
		checkedTx:    make(map[common.Hash]*types.Transaction),
		ethereum:     ethereum,
	}

	// register stake tx handler
	app.txDispatcher.RegisterTxHandler(constant.ModuleNameStake, &stake.StakeTxHandler{})

	return app, nil
}

// DeliverTx - ABCI
func (app *BaseApp) DeliverPtx(txBytes []byte) abci.ResponseDeliverTx {
	ptx, err := decodePtx(txBytes)
	if err != nil {
		app.logger.Error("DeliverTx: Received invalid transaction", "err", err)
		return errors.DeliverResult(err)
	}

	//TODO: filter out non-txs (maybe for dpos vote)
	response := app.EthApp.DeliverPtx(ptx)
	if response.Code != abci.CodeTypeOK {
		return response
	}

	txs := ptx.RawTxs()
	for i := 0; i < len(txs); i++ {
		tx, err := decodeTx(txs[i])
		if err != nil {
			app.logger.Error("DeliverTx: Received invalid transaction", "err", err)
			return errors.DeliverResult(err)
		}

		if !isEthTx(tx) {
			app.logger.Debug("DeliverTx: Received stake transaction", "tx", tx)
			response = app.txDispatcher.DeliverTx(app, tx)
			if response.Code != abci.CodeTypeOK {
				break
			}
		}
	}

	return response
}

// DeliverTx - ABCI
func (app *BaseApp) DeliverTx(txBytes []byte) abci.ResponseDeliverTx {
	fmt.Println("deliver new ptx")
	//TODO:workaround to route deliverTx to deliverPtx util tendermint deliverPtx logic ready
	if app.EthApp.IsPtxEnabled() {
		return app.DeliverPtx(txBytes)
	}

	tx, err := decodeTx(txBytes)
	if err != nil {
		app.logger.Error("DeliverTx: Received invalid transaction", "err", err)
		return errors.DeliverResult(err)
	}

	if isEthTx(tx) {
		if checkedTx, ok := app.checkedTx[tx.Hash()]; ok {
			tx = checkedTx
		} else {
			// FIXME: Need to modify ethereum backend to obtain chain ID
			if _, err := types.Sender(types.NewEIP155Signer(constant.ChainId), tx); err != nil {
				app.logger.Debug("DeliverTx: Received invalid transaction", "tx", tx, "err", err)
				return errors.DeliverResult(err)
			}
		}
		resp := app.EthApp.DeliverTx(tx)
		// app.logger.Debug("EthApp DeliverTx response: %v\n", resp)
		return resp
	}

	app.logger.Debug("DeliverTx: Received valid transaction", "tx", tx)

	return app.txDispatcher.DeliverTx(app, tx)
}

// CheckTx - ABCI
func (app *BaseApp) CheckPtx(txBytes []byte) abci.ResponseCheckTx {
	ptx, err := decodePtx(txBytes)
	if err != nil {
		app.logger.Error("CheckTx: Received invalid transaction", "err", err)
		return errors.CheckResult(err)
	}

	// if isEthTx(tx) {
	// 	resp := app.EthApp.CheckTx(tx)
	// 	app.logger.Debug("EthApp CheckTx response: %v\n", resp)
	// 	if resp.IsErr() {
	// 		return errors.CheckResult(goerr.New(resp.Error()))
	// 	}
	// 	app.checkedTx[tx.Hash()] = tx
	// 	return sdk.NewCheck(0, "").ToABCI()
	// }

	resp := app.EthApp.CheckPtx(ptx)

	app.logger.Debug("CheckTx: Received valid parallel transaction", "ptx", ptx)

	return resp
	/*
		ctx := ttypes.NewContext(app.GetChainID(), app.WorkingHeight(), app.ethereum)
		return app.checkHandler(ctx, app.Check(), tx)
	*/
}

// CheckTx - ABCI
func (app *BaseApp) CheckTx(txBytes []byte, local bool) abci.ResponseCheckTx {
	//TODO:checkTx will pass Parallel transaction currently, so do nothing here
	// if true {
	// 	return abci.ResponseCheckTx{Code: abci.CodeTypeOK}
	// }
	tx, err := decodeTx(txBytes)
	if err != nil {
		app.logger.Error("CheckTx: Received invalid transaction", "err", err)
		return errors.CheckResult(err)
	}
	app.logger.Debug("CheckTx: Received valid transaction", "tx", tx)
	//fmt.Println("CheckTx: Received valid transaction", "tx", tx.Nonce())
	hash := tx.Hash()
	if isEthTx(tx) {
		resp := app.EthApp.CheckTx(tx)
		app.logger.Debug("EthApp CheckTx response: %v\n", resp)
		if resp.IsErr() {
			if resp.Code == ultronTypes.ErrorTypeBadNonce {
				app.EthApp.backend.Ethereum().EventMux().Post(ethereum.TxPreEvent{Tx: tx, Local: local})
			}
			return errors.CheckResult(goerr.New(resp.Error()))
		} else {
			app.EthApp.backend.Ethereum().EventMux().Post(ethereum.TxPreEvent{Tx: tx, Local: local})
		}
		app.checkedTx[tx.Hash()] = tx
		return abci.ResponseCheckTx{0, hash[:], "", 0, 0}
		// return sdk.NewCheck(tx.Hash(), 0, "").ToABCI()
	} else if tx != nil {
		app.EthApp.backend.Ethereum().EventMux().Post(ethereum.TxPreEvent{Tx: tx, Local: local})
	}

	app.logger.Debug("CheckTx: Received valid transaction", "tx", tx)

	resp := app.txDispatcher.CheckTx(app, tx)
	resp.Data = hash[:]
	if !resp.IsErr() {
		//Also need post Non-eth transaction
		app.EthApp.backend.Ethereum().EventMux().Post(ethereum.TxPreEvent{Tx: tx, Local: local})
	}
	return resp
}

// GetTx hash(request hash), from(from type), to(to type)
// Response is the result, hash or tx: the result can be multi-hash or multi-tx
func (app *BaseApp) GetTx(req abci.RequestGetTx) (res abci.ResponseGetTx) {
	// hash := req.GetHash()
	from := req.GetFrom()
	to := req.GetTo()
	if from == tmTypes.ParallelTxHash && to == tmTypes.RawTxHash {
		// hash is the ptx contains tx hash and check if all tx exists
		// if dont contain the tx, return the tx hash
		// and tendermint would get the tx from remote peer
		// Note: the result can be multi-tx
	} else if from == tmTypes.RawTx && to == tmTypes.RawTx {
		// hash is the raw tx and return the tx
	} else if from == tmTypes.ParallelTxHash && to == tmTypes.ParallelTx {
		// hash is ptx hash and return the ptx with tx
	}
	return abci.ResponseGetTx{Code: abci.CodeTypeOK, Response: nil}
}

// BeginBlock - ABCI
func (app *BaseApp) BeginBlock(req abci.RequestBeginBlock) (res abci.ResponseBeginBlock) {
	app.EthApp.BeginBlock(req)
	app.AbsentValidators = req.AbsentValidators
	app.logger.Info("BeginBlock", "absentvalidators", app.AbsentValidators)
	app.ByzantineValidators = req.ByzantineValidators
	app.Random = req.Header.Random

	return abci.ResponseBeginBlock{}
}

// EndBlock - ABCI
func (app *BaseApp) EndBlock(req abci.RequestEndBlock) (res abci.ResponseEndBlock) {
	app.EthApp.EndBlock(req)
	totalUsedGasFee := app.EthApp.GetTotalUsedGasFee()

	// obtain validator set changes
	diff, err := stake.UpdateValidatorSet(app.Append(), app.Random.Seed)
	if err != nil {
		panic(err)
	}
	app.AddValChange(diff)

	// eliminate absent validators
	cs := stake.GetCandidates()
	cs.Sort()
	validators := cs.Validators()
	absence := make([]bool, len(validators))
	for _, i := range app.AbsentValidators {
		if int(i) < len(absence) {
			absence[i] = true
		}
	}

	presentValidators := stake.Validators{}
	for i, v := range validators {
		if !absence[i] {
			presentValidators = append(presentValidators, v)
		}
	}

	// block award
	stake.NewAwardCalculator(app.WorkingHeight(), presentValidators, totalUsedGasFee).AwardAll()

	// punish Byzantine validators
	if len(app.ByzantineValidators) > 0 {
		for _, bv := range app.ByzantineValidators {
			pk, err := utils.GetPubKey(string(bv.PubKey))
			if err != nil {
				continue
			}

			stake.PunishByzantineValidator(pk)
		}
		app.ByzantineValidators = app.ByzantineValidators[:0]
	}

	// todo punish those validators who has been absent for up to 3 hours
	app.EthApp.backend.UpdateProposer()
	return app.StoreApp.EndBlock(req)
}

func (app *BaseApp) Commit() (res abci.ResponseCommit) {
	app.checkedTx = make(map[common.Hash]*types.Transaction)
	app.EthApp.Commit()
	res = app.StoreApp.Commit()
	return
}

func (app *BaseApp) InitState(module, key, value string) error {
	state := app.Append()
	logger := app.Logger().With("module", module, "key", key)

	if module == sdk.ModuleNameBase {
		if key == sdk.ChainKey {
			app.info.SetChainID(state, value)
			return nil
		}
		logger.Error("Invalid genesis option")
		return nil
	}

	app.StoreApp.Committed().Set([]byte(key), []byte(value))
	err := app.txDispatcher.InitState(module, key, value, state)
	if err != nil {
		logger.Error("Invalid genesis option", "err", err)
	}
	return err
}

func isEthTx(tx *types.Transaction) bool {
	zero := big.NewInt(0)
	return tx.Data() == nil ||
		tx.GasPrice().Cmp(zero) != 0 ||
		tx.Gas().Cmp(zero) != 0 ||
		tx.Value().Cmp(zero) != 0 ||
		tx.To() != nil
}
