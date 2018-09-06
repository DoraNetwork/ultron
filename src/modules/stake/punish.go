package stake

import (
	"fmt"
	"math/big"

	"github.com/dora/ultron/commons"
	"github.com/dora/ultron/const"
	"github.com/dora/ultron/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tendermint/go-crypto"
)

const (
	byzantine_deduction_ratio = 5 // deduction ratio %5 for byzantine validators
	absent_deduction_ratio    = 1 // deduction ratio %1 for those validators absent for up to 3 hours
)

func PunishByzantineValidator(pubKey crypto.PubKey) (err error) {
	return punish(pubKey, byzantine_deduction_ratio, "Byzantine validator")
}

func PunishAbsentValidator(pubKey crypto.PubKey) (err error) {
	return punish(pubKey, absent_deduction_ratio, "Absent for up to 3 hours")
}

func punish(pubKey crypto.PubKey, ratio int64, reason string) (err error) {
	totalDeduction := new(big.Int)
	v := GetCandidateByPubKey(utils.PubKeyString(pubKey))
	if v == nil {
		return ErrNoCandidateForAddress()
	}

	v.Active = "N"
	v.UpdatedAt = utils.Now()
	updateCandidate(v)

	// Get all of the delegators(includes the validator itself)
	delegations := GetDelegationsByPubKey(v.PubKey)
	for _, delegation := range delegations {
		deduction := new(big.Int)
		deduction.Mul(delegation.ParseDelegateAmount(), big.NewInt(ratio))
		deduction.Div(deduction, big.NewInt(100))
		punishDelegator(delegation, v.OwnerAddress, deduction)
		totalDeduction.Add(totalDeduction, deduction)
	}

	// Save punishment history
	punishHistory := &PunishHistory{PubKey: pubKey, DeductionRatio: ratio, Deduction: totalDeduction, Reason: reason, CreatedAt: utils.Now()}
	savePunishHistory(punishHistory)

	return
}

func punishDelegator(d *Delegation, validatorAddress common.Address, amount *big.Int) {
	fmt.Printf("punish delegator, address: %s, amount: %d\n", d.DelegatorAddress.String(), amount)

	commons.Transfer(constant.StakeAccount, constant.MintAccount, amount)
	now := utils.Now()

	neg := new(big.Int).Neg(amount)
	d.AddDelegateAmount(neg)
	d.UpdatedAt = now
	UpdateDelegation(d)

	// accumulate shares of the validator
	val := GetCandidateByAddress(validatorAddress)
	val.AddShares(neg)
	val.UpdatedAt = now
	updateCandidate(val)
}
