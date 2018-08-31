package ethereum

import (
	"bytes"
	"math/big"
	"fmt"
	"github.com/dora/ultron/const"
	"github.com/ethereum/go-ethereum/common"
)

type EthStateWrapper struct {
	*EthState
	TotalUsedGasFee *big.Int
}

type Remittance struct {
	From   common.Address
	To     common.Address
	Amount *big.Int
}

var (
	remittanceLedger []Remittance = make([]Remittance, 0)
)

func NewEthStateWrapper() *EthStateWrapper {
	return &EthStateWrapper{
		EthState: NewEthState(),
		TotalUsedGasFee: big.NewInt(0),
	}
}

func SubmitRemittance(remittance Remittance) {
	remittanceLedger = append(remittanceLedger, remittance)
}

func (es *EthStateWrapper) EndBlock() {
	es.EthState.EndBlock()
	es.TotalUsedGasFee = es.EthState.work.totalUsedGasFee
}

func (es *EthStateWrapper) Commit(receiver common.Address) (common.Hash, error) {
	es.EthState.work.handleRemittanceLedger()
	// clear remittance ledger
	remittanceLedger = make([]Remittance, 0)
	// clear total used gas fee
	es.TotalUsedGasFee = big.NewInt(0)

	return es.EthState.Commit(receiver)
}

func (ws *workState) handleRemittanceLedger() {
	for i := 0; i < len(remittanceLedger); i++ {
		scObj := remittanceLedger[i]
		if bytes.Compare(scObj.From.Bytes(), constant.MintAccount.Bytes()) == 0 {
			if bytes.Compare(scObj.To.Bytes(), constant.MintAccount.Bytes()) != 0 {
				if (constant.DEBUG_STAKE) {
					fmt.Printf("##### %s -> %s, %s\n", scObj.From.String(), scObj.To.String(), scObj.Amount.String())
				}
				ws.state.AddBalance(scObj.To, scObj.Amount)
			}
		} else {
			if ws.state.GetBalance(scObj.From).Cmp(scObj.Amount) >= 0 {
				ws.state.SubBalance(scObj.From, scObj.Amount)
				if bytes.Compare(scObj.To.Bytes(), constant.MintAccount.Bytes()) != 0 {
					if (constant.DEBUG_STAKE) {
						fmt.Printf("##### %s -> %s, %s\n", scObj.From.String(), scObj.To.String(), scObj.Amount.String())
					}
					ws.state.AddBalance(scObj.To, scObj.Amount)
				}
			} else {
				fmt.Printf("ERROR: insufficient balance in %s", scObj.From.String())
			}
		}
	}
}
