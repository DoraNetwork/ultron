package stake

import (
	"fmt"
	"math"
	"math/big"

	"github.com/dora/ultron/commons"
	"github.com/dora/ultron/const"
	"github.com/dora/ultron/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tendermint/go-crypto"
)

type awardCalculator struct {
	height          int64
	validators      Validators
	transactionFees *big.Int
}

type validator struct {
	shares           *big.Int
	ownerAddress     common.Address
	pubKey           crypto.PubKey
	delegators       []delegator
	cut              float64
	sharesPercentage *big.Float
}

type delegator struct {
	address common.Address
	shares  *big.Int
}

const (
	inflationRate       = 5
	yearlyBlockNumber   = 365 * 24 * 3600 / 10
	basicMintableAmount = "1000000000000000000000000000"
)

func NewAwardCalculator(height int64, validators Validators, transactionFees *big.Int) *awardCalculator {
	fmt.Printf("new award calculator, height: %d, transaction fees: %d\n", height, transactionFees)
	return &awardCalculator{height, validators, transactionFees}
}

func (ac awardCalculator) getMintableAmount() (result *big.Int) {
	result = new(big.Int)
	base, ok := new(big.Float).SetString(basicMintableAmount)
	if !ok {
		return
	}

	year := ac.height / yearlyBlockNumber
	pow := big.NewFloat(math.Pow(float64(1+inflationRate/100), float64(year)))
	new(big.Float).Mul(base, pow).Int(result)
	fmt.Printf("year: %d, mintable amount: %v\n", year, result)
	return
}

func (ac awardCalculator) getTotalBlockAward() (result *big.Int) {
	blocks := big.NewInt(yearlyBlockNumber)
	result = new(big.Int)
	result.Mul(ac.getMintableAmount(), big.NewInt(inflationRate))
	result.Div(result, big.NewInt(100))
	result.Div(result, blocks)
	fmt.Printf("yearly block number: %d, total block award: %v\n", blocks, result)
	return
}

func (ac awardCalculator) AwardAll() {
	var validators []validator
	totalShares := new(big.Int)

	for _, val := range ac.validators {
		var validator validator
		var delegators []delegator
		candidate := GetCandidateByAddress(val.OwnerAddress)
		if candidate.Shares == "0" {
			continue
		}

		shares := candidate.ParseShares()
		validator.shares = shares
		validator.ownerAddress = candidate.OwnerAddress
		validator.pubKey = candidate.PubKey
		validator.cut = candidate.ParseCompRate()
		totalShares.Add(totalShares, shares)

		// Get all of the delegators
		delegations := GetDelegationsByPubKey(candidate.PubKey)
		for _, delegation := range delegations {
			delegator := delegator{}
			delegator.address = delegation.DelegatorAddress
			delegator.shares = delegation.Shares()
			delegators = append(delegators, delegator)
		}
		validator.delegators = delegators
		validators = append(validators, validator)
	}

	totalAward := ac.getTotalBlockAward()
	actualTotalAward := big.NewInt(0)
	for _, val := range validators {
		actualAward := award(val, totalShares, ac, big.NewInt(0))
		actualTotalAward.Add(actualTotalAward, actualAward)
	}

	// If there is remaining award, distribute a second round based on stake amount.
	remaining := new(big.Int).Sub(totalAward, actualTotalAward)
	if remaining.Cmp(big.NewInt(0)) > 0 {
		fmt.Printf("there is remaining award, distribute a second round based on stake amount. remaining: %d\v", remaining)
		for _, val := range validators {
			award(val, totalShares, ac, remaining)
		}
	}
}

func award(val validator, totalShares *big.Int, ac awardCalculator, remaining *big.Int) (actualAward *big.Int) {
	again := !(remaining.Cmp(big.NewInt(0)) == 0)
	x := new(big.Float).SetInt(val.shares)
	y := new(big.Float).SetInt(totalShares)
	val.sharesPercentage = new(big.Float).Quo(x, y)
	if !again && val.sharesPercentage.Cmp(big.NewFloat(0.1)) > 0 {
		val.sharesPercentage = big.NewFloat(0.1)
	}

	fmt.Printf("val.shares: %f, totalShares: %f, percentage: %f\n", x, y, val.sharesPercentage)

	if again {
		actualAward = ac.getRemainingAwardForValidator(val, remaining)
	} else {
		actualAward = ac.getBlockAwardForValidator(val)
	}

	remainingAward := actualAward

	// award to delegators
	for _, delegator := range val.delegators {
		delegatorAward := ac.getDelegatorAward(delegator, val, actualAward)
		remainingAward.Sub(remainingAward, delegatorAward)
		ac.awardToDelegator(delegator, val, delegatorAward)
	}
	ac.awardToValidator(val, remainingAward)

	return
}

func (ac awardCalculator) getBlockAwardForValidator(val validator) (result *big.Int) {
	blockAward := new(big.Int)
	blockAward.Add(ac.getTotalBlockAward(), ac.transactionFees)
	return ac.getAwardForValidator(val, blockAward)
}

func (ac awardCalculator) getRemainingAwardForValidator(val validator, remaining *big.Int) (result *big.Int) {
	return ac.getAwardForValidator(val, remaining)
}

func (ac awardCalculator) getAwardForValidator(val validator, award *big.Int) (result *big.Int) {
	result = new(big.Int)
	z := new(big.Float).SetInt(award)
	z.Mul(z, val.sharesPercentage)
	z.Int(result)
	fmt.Printf("shares percentage: %v, award for validator: %v\n", val.sharesPercentage, result)
	return
}

func (ac awardCalculator) getDelegatorAward(del delegator, val validator, blockAward *big.Int) (result *big.Int) {
	result = new(big.Int)
	z := new(big.Float)
	x := new(big.Float).SetInt(del.shares) // shares of the delegator
	y := new(big.Float).SetInt(val.shares) // total shares of the validator
	z.Quo(x, y)
	fmt.Printf("delegator shares: %f, validator shares: %f, percentage: %f\n", x, y, z)
	award := new(big.Float).SetInt(blockAward)
	z.Mul(z, award)
	cut := big.NewFloat(val.cut)
	z.Mul(z, cut)
	z.Int(result)
	fmt.Printf("delegator award: %d\n", result)
	return
}

func (ac awardCalculator) awardToValidator(v validator, award *big.Int) {
	fmt.Printf("award to validator, owner_address: %s, award: %d\n", v.ownerAddress.String(), award)

	// validator is also a delegator
	d := delegator{address: v.ownerAddress}
	ac.awardToDelegator(d, v, award)
}

func (ac awardCalculator) awardToDelegator(d delegator, v validator, award *big.Int) {
	fmt.Printf("award to delegator, address: %s, amount: %d\n", d.address.String(), award)
	commons.Transfer(constant.MintAccount, constant.StakeAccount, award)
	now := utils.Now()

	// add award to stake of the delegator
	delegation := GetDelegation(d.address, v.pubKey)
	if delegation == nil {
		return
	}

	delegation.AddAwardAmount(award)
	delegation.UpdatedAt = now
	UpdateDelegation(delegation)

	// accumulate shares of the validator
	val := GetCandidateByAddress(v.ownerAddress)
	val.AddShares(award)
	val.UpdatedAt = now
	updateCandidate(val)
}
