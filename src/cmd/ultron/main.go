package main

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/tendermint/tmlibs/cli"

	basecmd "github.com/dora/ultron/node/commands"
	"github.com/cosmos/cosmos-sdk/client/commands/auto"
)

// UltronCmd is the entry point for this binary
var (
	UltronCmd = &cobra.Command{
		Use:   "ultron",
		Short: "Ultron Network",
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Help()
		},
	}

	lineBreak = &cobra.Command{Run: func(*cobra.Command, []string) {}}
)

func main() {
	// disable sorting
	cobra.EnableCommandSorting = false

	// add commands
	prepareNodeCommands()

	UltronCmd.AddCommand(
		nodeCmd,

		lineBreak,
		auto.AutoCompleteCmd,
	)

	// prepare and add flags
	basecmd.SetUpRoot(UltronCmd)
	executor := cli.PrepareMainCmd(UltronCmd, "UL", os.ExpandEnv("$HOME/.ultron-cli"))
	executor.Execute()
}
