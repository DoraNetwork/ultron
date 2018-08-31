package backend

import (
	"bytes"
	"fmt"
	"time"

	"github.com/dora/ultron/backend/ethereum"
	"github.com/dora/ultron/errors"
	"github.com/ethereum/go-ethereum/core"
	ethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
	rpcClient "github.com/tendermint/tendermint/rpc/client"
	ctypes "github.com/tendermint/tendermint/rpc/core/types"
	tmTypes "github.com/tendermint/tendermint/types"
	//wire "github.com/tendermint/go-wire"
	emtConfig "github.com/dora/ultron/node/config"
)

var (
	local = false
	broadcastPtxHash = true
)

//----------------------------------------------------------------------
// Transactions sent via the go-ethereum rpc need to be routed to tendermint

// listen for txs and forward to tendermint
func (b *Backend) txBroadcastLoop() {
	b.txSub = b.ethereum.EventMux().Subscribe(core.TxPreEvent{})
	b.ptxSub = b.ethereum.EventMux().Subscribe(ethereum.PtxPreEvent{})

	for tries := 0; tries < 3; tries++ { // wait a moment for localClient initialized properly
		time.Sleep(time.Second)
		if b.localClient != nil {
			if _, err := b.localClient.Status(); err != nil {
				log.Info("Using local client for forwarding tx to tendermint!")
				local = true
				break
			}
		}
	}
	
	testConfig, _ := emtConfig.ParseConfig()
	if (testConfig != nil && !testConfig.TestConfig.UsePtxHash) {
		broadcastPtxHash = false
	}

	if !local {
		waitForServer(b.client)
	}

	// for obj := range b.txSub.Chan() {
	// 	event := obj.Data.(core.TxPreEvent)
	// 	result, err := b.BroadcastTxSync(event.Tx)
	// 	if err != nil {
	// 		log.Error("Broadcast error", "err", err)
	// 	} else {
	// 		if result.Code != uint32(0) {
	// 			go removeTx(b, event.Tx)
	// 		} else {
	// 			// TODO: do something else?
	// 		}
	// 	}
	// }

	for {
		select {
		case txObj := <-b.txSub.Chan():
			//monitor tx
			//cast data from core.TxPreEvent to ethereum.TxPreEvent
			// event := ethereum.TxPreEvent{Tx:txObj.Data.(core.TxPreEvent).Tx, Local:true}
			// b.ethereum.EventMux().Post(event)
			event := txObj.Data.(core.TxPreEvent)
			//fmt.Println("new tx", event.Tx.Nonce())
			result, err := b.BroadcastTxSync(event.Tx)
			if err != nil {
				log.Error("Broadcast error", "err", err)
			} else {
				if result.Code != uint32(0) && result.Code != errors.ErrorTypeBadNonce {
					go removeTx(b, event.Tx)
				} else {
					// TODO: do something else?
				}
			}
		case ptxObj := <-b.ptxSub.Chan():
			//monitor tx
			event := ptxObj.Data.(ethereum.PtxPreEvent)
			fmt.Println("broadcast new ptx", event.Ptx.Hash().Hex())
			//monitor ptx
			//TODO:assign nil to avoid compile error
			// event.Ptx = nil
			//TODO:
			result, err := b.BroadcastPtxSync(event.Ptx)
			if err != nil {
				log.Error("Broadcast error", "err", err)
			} else {
				if result.Code != uint32(0) {
					//TODO:
					// go removeTx(b, event.Tx)
				} else {
					// TODO: do something else?
				}
			}
		}
	}
}

// BroadcastTx broadcasts a transaction to tendermint core
// #unstable
func (b *Backend) BroadcastTxSync(tx *ethTypes.Transaction) (*ctypes.ResultBroadcastTx, error) {
	buf := new(bytes.Buffer)
	if err := tx.EncodeRLP(buf); err != nil {
		return nil, err
	}

	if local {
		return b.localClient.BroadcastTxSync(buf.Bytes(), tmTypes.RawTx)
	} else {
		return b.client.BroadcastTxSync(buf.Bytes(), tmTypes.RawTx)
	}

}

func (b *Backend) BroadcastPtxSync(ptx *ethereum.ParalleledTransaction) (*ctypes.ResultBroadcastTx, error) {
	buf := new(bytes.Buffer)
	if err := ptx.EncodeRLP(buf); err != nil {
		return nil, err
	}
	txtype := tmTypes.ParallelTxHash
	if (!broadcastPtxHash) {
		txtype = tmTypes.ParallelTx
	}
	if local {
		return b.localClient.BroadcastTxSync(buf.Bytes(), txtype)
	} else {
		return b.client.BroadcastTxSync(buf.Bytes(), txtype)
	}
	// msg := &tmPtxMessage{Tx: buf.Bytes()}
	// send := wire.BinaryBytes(struct{ tmAppTxMessage }{msg})

	// //TODO:Need switch to BroadcastPtxSync
	// if local {
	// 	return b.localClient.BroadcastTxSync(send)
	// } else {
	// 	return b.client.BroadcastTxSync(send)
	// }
}

func (b *Backend) BroadcastTxCommit(tx *ethTypes.Transaction) (*ctypes.ResultBroadcastTxCommit, error) {
	buf := new(bytes.Buffer)
	if err := tx.EncodeRLP(buf); err != nil {
		return nil, err
	}

	if local {
		return b.localClient.BroadcastTxCommit(buf.Bytes())
	} else {
		return b.client.BroadcastTxCommit(buf.Bytes())
	}
}

//----------------------------------------------------------------------
// wait for Tendermint to open the socket and run http endpoint

func waitForServer(c *rpcClient.HTTP) {
	for {
		_, err := c.Status()
		if err == nil {
			break
		}

		log.Info("Waiting for tendermint endpoint to start", "err", err)
		time.Sleep(time.Second * 3)
	}
}

func removeTx(b *Backend, tx *ethTypes.Transaction) {
	b.Ethereum().TxPool().Remove(tx.Hash())
}
