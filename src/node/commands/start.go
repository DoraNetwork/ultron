package commands

import (
	"time"
	"fmt"
	"os"
	"bytes"
	"path"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/cosmos/cosmos-sdk/version"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/common"
	"github.com/tendermint/tmlibs/cli"
	cmn "github.com/tendermint/tmlibs/common"

	"github.com/dora/ultron/app"
	"github.com/dora/ultron/genesis"
)

var (
	PlayFlag = "play"
)

// GetStartCmd - initialize a command as the start command with tick
func GetStartCmd() *cobra.Command {
	startCmd := &cobra.Command{
		Use:   "start",
		Short: "Start this full node",
		RunE:  startCmd(),
	}

	startCmd.Flags().String(PlayFlag, "true", "Play test scripts")

	return startCmd
}

// nolint TODO: move to config file
const EyesCacheSize = 10000

//returns the start command which uses the tick
func startCmd() func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		rootDir := viper.GetString(cli.HomeFlag)

		cmdName := cmd.Root().Name()
		appName := fmt.Sprintf("%s v%v", cmdName, version.Version)
		storeApp, err := app.NewStoreApp(
			appName,
			path.Join(rootDir, "data", "merkleeyes.db"),
			EyesCacheSize,
			logger.With("module", "app"))
		if err != nil {
			return err
		}

		return start(rootDir, storeApp)
	}
}

func start(rootDir string, storeApp *app.StoreApp) error {
	srvs, err := startServices(rootDir, storeApp)
	if err != nil {
		return errors.Errorf("Error in start services: %v\n", err)
	}

	mode := viper.GetString(PlayFlag)
	switch mode {
	case "loop" :
		err = playLoopBasicTx(srvs, rootDir)
	default:
	}

	// wait forever
	cmn.TrapSignal(func() {
		srvs.tmNode.Stop()
	})

	return nil
}

func playLoopBasicTx(srv *Services, rootDir string) error {
	txCnt := 8192
	accounts, err := initAccountsForPtxTest(srv, rootDir, txCnt)
	if err != nil {
		return fmt.Errorf("ERROR: %s", err)
	}

	remoteClientCnt := 8
	httpClients := createRemoteClientConnections(remoteClientCnt)
	fmt.Println("!!!!!!!!!!!!!!!!!! create", len(httpClients), "remote clients.")

	txsCh, _ := prepareTXsAsync(srv, txCnt, accounts)

	go func() {
		tick := 0
		for true {
			start := time.Now()
			fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Start time:", start)

			queuedTxHash := []common.Hash{}
			txsBytes := [][]byte{}
			select {
			case txs := <-txsCh :
				fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Tx Received!")
				for _, signedTx := range txs {
					buf := new(bytes.Buffer)
					signedTx.EncodeRLP(buf)
					txsBytes = append(txsBytes, buf.Bytes())
					queuedTxHash = append(queuedTxHash, signedTx.Hash())
				}
				start = time.Now()
				fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ", len(txsBytes), "Tx Received!")
				wg := addTxsToHTTPClientAsync(httpClients, txsBytes)
				wg.Wait()
			}
	
			end := time.Now()
			fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! Add ", txCnt, " tx in", remoteClientCnt, "costs :", end.Sub(start))
		
			if tick % 3 == 0 {
//			    time.Sleep(3 * time.Second)
			    err = waitTxsAsync(srv, queuedTxHash[txCnt - 1:])
			    if err != nil {
			        fmt.Println("ERROR: waitTxsAsync meets error", err)
			    }
			}

			tick++
//			err = waitTxsAsync(srv, queuedTxHash)
//			if err != nil {
//				fmt.Println("")
//			}
		}
	}()

	return nil
}


func createBaseCoinApp(rootDir string, storeApp *app.StoreApp, ethApp *app.EthermintApplication, ethereum *eth.Ethereum) (*app.BaseApp, error) {
	ultronApp, err := app.NewBaseApp(storeApp, ethApp, ethereum)
	if err != nil {
		return nil, err
	}
	// if chain_id has not been set yet, load the genesis.
	// else, assume it's been loaded
	if ultronApp.GetChainID() == "" {
		// If genesis file exists, set key-value options
		genesisFile := path.Join(rootDir, "genesis.json")
		if _, err := os.Stat(genesisFile); err == nil {
			err = genesis.Load(ultronApp, genesisFile)
			if err != nil {
				return nil, errors.Errorf("Error in LoadGenesis: %v\n", err)
			}
		} else {
			fmt.Printf("No genesis file at %s, skipping...\n", genesisFile)
		}
	}

	chainID := ultronApp.GetChainID()
	logger.Info("Starting Ultron", "chain_id", chainID)

	return ultronApp, nil
}
