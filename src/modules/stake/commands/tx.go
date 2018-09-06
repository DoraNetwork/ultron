package commands

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/tendermint/go-crypto"

	txcmd "github.com/dora/ultron/client/commands/txs"
	"github.com/dora/ultron/modules/stake"
	"github.com/dora/ultron/utils"
	"github.com/ethereum/go-ethereum/common"
	"math/big"
)

/*
The stake/declare tx allows a potential validator to declare its candidacy. Signed by the validator.

* Validator address

The stake/slot/propose tx allows a potential validator to offer a slot tokens and corresponding ROI. It returns a tx ID. Signed by the validator.

* Validator address
* Token amount
* Proposed ROI

The stake/slot/accept tx is used by a delegator to accept and stake tokens for an ID. Signed by the user.

* Slot ID
* Token amount
* Delegator address

The stake/slot/cancel tx is to cancel all remianing amounts from an unaccepted slot by its creator using the ID. Signed by the validator.

* Slot ID
* Validator address
*/

// nolint
const (
	FlagPubKey           = "pubkey"
	FlagAmount           = "amount"
	FlagMaxAmount        = "max-amount"
	FlagCompRate         = "comp-rate"
	FlagAddress          = "address"
	FlagValidatorAddress = "validator-address"
	FlagWebsite          = "website"
	FlagLocation         = "location"
	FlagDetails          = "details"
	FlagVerified         = "verified"
)

// nolint
var (
	CmdDeclareCandidacy = &cobra.Command{
		Use:   "declare-candidacy",
		Short: "Allows a potential validator to declare its candidacy",
		RunE:  cmdDeclareCandidacy,
	}
	CmdUpdateCandidacy = &cobra.Command{
		Use:   "update-candidacy",
		Short: "Allows a validator candidate to change its candidacy",
		RunE:  cmdUpdateCandidacy,
	}
	CmdWithdrawCandidacy = &cobra.Command{
		Use:   "withdraw-candidacy",
		Short: "Allows a validator/candidate to withdraw",
		RunE:  cmdWithdrawCandidacy,
	}
	CmdVerifyCandidacy = &cobra.Command{
		Use:   "verify-candidacy",
		Short: "Allows the foundation to verify a validator/candidate's information",
		RunE:  cmdVerifyCandidacy,
	}
	CmdActivateCandidacy = &cobra.Command{
		Use:   "activate-candidacy",
		Short: "Allows a validator activate itself",
		RunE:  cmdActivateCandidacy,
	}
	CmdDelegate = &cobra.Command{
		Use:   "delegate",
		Short: "Delegate coins to an existing validator/candidate",
		RunE:  cmdDelegate,
	}
	CmdWithdraw = &cobra.Command{
		Use:   "withdraw",
		Short: "Withdraw coins from a validator/candidate",
		RunE:  cmdWithdraw,
	}
)

func init() {

	// define the flags
	fsPk := flag.NewFlagSet("", flag.ContinueOnError)
	fsPk.String(FlagPubKey, "", "PubKey of the validator-candidate")

	fsAmount := flag.NewFlagSet("", flag.ContinueOnError)
	fsAmount.String(FlagAmount, "", "Amount of tokens")

	fsCandidate := flag.NewFlagSet("", flag.ContinueOnError)
	fsCandidate.String(FlagMaxAmount, "", "Max amount to be staked")
	fsCandidate.String(FlagWebsite, "", "optional website")
	fsCandidate.String(FlagLocation, "", "optional location")
	fsCandidate.String(FlagDetails, "", "optional detailed description")

	fsCompRate := flag.NewFlagSet("", flag.ContinueOnError)
	fsCompRate.String(FlagCompRate, "0", "The compensation percentage of block awards to be distributed to the validator")

	fsAddr := flag.NewFlagSet("", flag.ContinueOnError)
	fsAddr.String(FlagAddress, "", "Account address")

	fsVerified := flag.NewFlagSet("", flag.ContinueOnError)
	fsVerified.String(FlagVerified, "false", "true or false")

	fsValidatorAddress := flag.NewFlagSet("", flag.ContinueOnError)
	fsValidatorAddress.String(FlagValidatorAddress, "", "validator address")

	// add the flags
	CmdDeclareCandidacy.Flags().AddFlagSet(fsPk)
	CmdDeclareCandidacy.Flags().AddFlagSet(fsCandidate)
	CmdDeclareCandidacy.Flags().AddFlagSet(fsCompRate)

	CmdUpdateCandidacy.Flags().AddFlagSet(fsCandidate)

	CmdVerifyCandidacy.Flags().AddFlagSet(fsValidatorAddress)
	CmdVerifyCandidacy.Flags().AddFlagSet(fsVerified)

	CmdDelegate.Flags().AddFlagSet(fsValidatorAddress)
	CmdDelegate.Flags().AddFlagSet(fsAmount)

	CmdWithdraw.Flags().AddFlagSet(fsValidatorAddress)
	CmdWithdraw.Flags().AddFlagSet(fsAmount)
}

func cmdDeclareCandidacy(cmd *cobra.Command, args []string) error {
	pk, err := GetPubKey(viper.GetString(FlagPubKey))
	if err != nil {
		return err
	}

	maxAmount := viper.GetString(FlagMaxAmount)
	v := new(big.Int)
	_, ok := v.SetString(maxAmount, 10)
	if !ok || v.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("max-amount must be positive interger")
	}

	compRate := viper.GetString(FlagCompRate)
	fCompRate := utils.ParseFloat(compRate)
	if fCompRate <= 0 || fCompRate >= 1 {
		return fmt.Errorf("comp-rate must between 0 and 1")
	}

	description := stake.Description{
		Website:  viper.GetString(FlagWebsite),
		Location: viper.GetString(FlagLocation),
		Details:  viper.GetString(FlagDetails),
	}

	tx := stake.NewTxDeclareCandidacy(pk, maxAmount, compRate, description)
	return txcmd.DoTx(tx)
}

func cmdUpdateCandidacy(cmd *cobra.Command, args []string) error {
	maxAmount := viper.GetString(FlagMaxAmount)
	if maxAmount != "" {
		v := new(big.Int)
		_, ok := v.SetString(maxAmount, 10)
		if !ok || v.Cmp(big.NewInt(0)) <= 0 {
			return fmt.Errorf("max-amount must be positive interger")
		}
	}

	description := stake.Description{
		Website:  viper.GetString(FlagWebsite),
		Location: viper.GetString(FlagLocation),
		Details:  viper.GetString(FlagDetails),
	}

	tx := stake.NewTxUpdateCandidacy(maxAmount, description)
	return txcmd.DoTx(tx)
}

func cmdWithdrawCandidacy(cmd *cobra.Command, args []string) error {
	tx := stake.NewTxWithdrawCandidacy()
	return txcmd.DoTx(tx)
}

func cmdVerifyCandidacy(cmd *cobra.Command, args []string) error {
	candidateAddress := common.HexToAddress(viper.GetString(FlagValidatorAddress))
	if candidateAddress.String() == "" {
		return fmt.Errorf("please enter candidate address using --validator-address")
	}

	verified := viper.GetBool(FlagVerified)
	tx := stake.NewTxVerifyCandidacy(candidateAddress, verified)
	return txcmd.DoTx(tx)
}

func cmdActivateCandidacy(cmd *cobra.Command, args []string) error {
	tx := stake.NewTxActivateCandidacy()
	return txcmd.DoTx(tx)
}

func cmdDelegate(cmd *cobra.Command, args []string) error {
	amount := viper.GetString(FlagAmount)
	v := new(big.Int)
	_, ok := v.SetString(amount, 10)
	if !ok || v.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("amount must be positive interger")
	}

	validatorAddress := common.HexToAddress(viper.GetString(FlagValidatorAddress))
	if validatorAddress.String() == "" {
		return fmt.Errorf("please enter validator address using --validator-address")
	}

	tx := stake.NewTxDelegate(validatorAddress, amount)
	return txcmd.DoTx(tx)
}

func cmdWithdraw(cmd *cobra.Command, args []string) error {
	validatorAddress := common.HexToAddress(viper.GetString(FlagValidatorAddress))
	if validatorAddress.String() == "" {
		return fmt.Errorf("please enter validator address using --validator-address")
	}

	amount := viper.GetString(FlagAmount)
	v := new(big.Int)
	_, ok := v.SetString(amount, 10)
	if !ok || v.Cmp(big.NewInt(0)) <= 0 {
		return fmt.Errorf("amount must be positive interger")
	}

	tx := stake.NewTxWithdraw(validatorAddress, amount)
	return txcmd.DoTx(tx)
}

// GetPubKey - create the pubkey from a pubkey string
func GetPubKey(pubKeyStr string) (pk crypto.PubKey, err error) {
	if len(pubKeyStr) == 0 {
		err = fmt.Errorf("must use --pubkey flag")
		return
	}
	if len(pubKeyStr) != 64 { //if len(pkBytes) != 32 {
		err = fmt.Errorf("pubkey must be Ed25519 hex encoded string which is 64 characters long")
		return
	}
	var pkBytes []byte
	pkBytes, err = hex.DecodeString(pubKeyStr)
	if err != nil {
		return
	}
	var pkEd crypto.PubKeyEd25519
	copy(pkEd[:], pkBytes[:])
	pk = pkEd.Wrap()
	return
}
