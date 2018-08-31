package main

import (
	"github.com/spf13/cobra"

	txcmd "github.com/dora/ultron/client/commands/txs"
	stakecmd "github.com/dora/ultron/modules/stake/commands"
	"github.com/cosmos/cosmos-sdk/client/commands"
	"github.com/cosmos/cosmos-sdk/client/commands/query"
)

// clientCmd is the entry point for this binary
var clientCmd = &cobra.Command{
	Use:   "client",
	Short: "Ultron light client",
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func prepareClientCommands() {
	commands.AddBasicFlags(clientCmd)

	query.RootCmd.AddCommand(
		stakecmd.CmdQueryValidator,
		stakecmd.CmdQueryValidators,
		stakecmd.CmdQueryDelegator,
	)

	txcmd.RootCmd.AddCommand(
		stakecmd.CmdDeclareCandidacy,
		stakecmd.CmdUpdateCandidacy,
		stakecmd.CmdWithdrawCandidacy,
		stakecmd.CmdVerifyCandidacy,
		stakecmd.CmdActivateCandidacy,
		stakecmd.CmdDelegate,
		stakecmd.CmdWithdraw,
	)

	clientCmd.AddCommand(
		txcmd.RootCmd,
		query.RootCmd,
		lineBreak,

		commands.InitCmd,
		commands.ResetCmd,
	)
}
