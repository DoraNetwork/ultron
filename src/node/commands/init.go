package commands

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	ethUtils "github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/log"
	"github.com/tendermint/tendermint/types"
	cmn "github.com/tendermint/tmlibs/common"

	emtUtils "github.com/dora/ultron/backend/cmd/utils"
)

var (
	FlagChainID = "chain-id"
	DockerMode  = "docker"
	DockerNodeID = "docker-id"
)

var InitCmd = GetInitCmd()

func GetInitCmd() *cobra.Command {
	initCmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize",
		RunE:  initFiles,
	}
	initCmd.Flags().String(FlagChainID, "local", "Chain ID")
	initCmd.Flags().Int(DockerMode, 0, "Docker Cluster Size")
	initCmd.Flags().Int(DockerNodeID, 0, "Docker Cluster ID, A int ID Less Equal DockerMode")
	return initCmd
}

func initFiles(cmd *cobra.Command, args []string) error {
	initTendermint()
	return initEthermint(args)
}

func initTendermint() {
	dockerMode := viper.GetInt(DockerMode)
	if dockerMode > 0 {
		dockerID := viper.GetInt(DockerNodeID)
		initTendermintDockerMode(dockerMode, dockerID)
	}
	
	// private validator
	privValFile := config.TMConfig.PrivValidatorFile()
	var privValidator *types.PrivValidatorFS
	if cmn.FileExists(privValFile) {
		privValidator = types.LoadPrivValidatorFS(privValFile)
		logger.Info("Found private validator", "path", privValFile)
	} else {
		privValidator = types.GenPrivValidatorFS(privValFile)
		privValidator.Save()
		logger.Info("Genetated private validator", "path", privValFile)
	}

	// genesis file
	genFile := config.TMConfig.GenesisFile()
	if cmn.FileExists(genFile) {
		logger.Info("Found genesis file", "path", genFile)
	} else {
		genDoc := GenesisDoc{
			ChainID:                 viper.GetString(FlagChainID),
			MaxVals:                 4,
			ReserveRequirementRatio: "0.1",
		}
		genDoc.Validators = []GenesisValidator{{
			PubKey:    privValidator.GetPubKey(),
			Power:     1000,
			Address:   "0x4806202cd62b03be5f6681827d5329409c1e0cdd",
			Cut:       "0.5",
			MaxAmount: 10000,
		}}

		if err := genDoc.SaveAs(genFile); err != nil {
			panic(err)
		}
		logger.Info("Genetated genesis file", "path", genFile)
	}
}

func initTendermintDockerMode(dockerCluster int, dockerID int) {
	if (dockerCluster > len(defaultAccounts)) {
		logger.Error("ERROR: dockerCluster > len(defaultAccounts.")
		return
	}

	// private validator
	privValFile := config.TMConfig.PrivValidatorFile()
	if cmn.FileExists(privValFile) {
		types.LoadPrivValidatorFS(privValFile)
		logger.Info("Found private validator", "path", privValFile)
	} else {
		privValidator := types.GenPrivValidatorFS(privValFile)
		json.Unmarshal([]byte(privValidatorsMap[dockerID]), privValidator)
		privValidator.Save()
		logger.Info("Genetated private validator", "path", privValFile)
	}

	// genesis file
	genFile := config.TMConfig.GenesisFile()
	if cmn.FileExists(genFile) {
		logger.Info("Found genesis file", "path", genFile)
	} else {
		genDoc := GenesisDoc{
			ChainID:                 viper.GetString(FlagChainID),
			MaxVals:                 4,
			ReserveRequirementRatio: "0.1",
		}
		genDoc.Validators = []GenesisValidator{}

		for i := 0; i < dockerCluster; i++ {
			privValidator := types.PrivValidatorFS{}
			json.Unmarshal([]byte(privValidatorsMap[i]), &privValidator)
			pubKey := privValidator.PubKey
			validator := GenesisValidator{
				PubKey:    pubKey,
				Power:     1000,
				Address:   defaultAccounts[i],
				Cut:       "0.5",
				MaxAmount: 10000,
			}
			genDoc.Validators = append(genDoc.Validators, validator)
		}

		if err := genDoc.SaveAs(genFile); err != nil {
			panic(err)
		}
		logger.Info("Genetated genesis file", "path", genFile)
	}
}

func initEthermint(args []string) error {
	genesisPath := ""
	if len(args) > 0 {
		genesisPath = args[0]
	}
	genesis, err := emtUtils.ParseGenesisOrDefault(genesisPath)
	if err != nil {
		ethUtils.Fatalf("genesisJSON err: %v", err)
	}
	// override ethermint's chain_id
	genesis.Config.ChainId = new(big.Int).SetUint64(uint64(config.EMConfig.EthChainId))

	ethermintDataDir := emtUtils.MakeDataDir(context)

	chainDb, err := ethdb.NewLDBDatabase(filepath.Join(ethermintDataDir,
		"ultron/chaindata"), 0, 0)
	if err != nil {
		ethUtils.Fatalf("could not open database: %v", err)
	}

	_, hash, err := core.SetupGenesisBlock(chainDb, genesis)
	if err != nil {
		ethUtils.Fatalf("failed to write genesis block: %v", err)
	}

	log.Info("successfully wrote genesis block and/or chain rule set", "hash", hash)

	// As per https://github.com/tendermint/ethermint/issues/244#issuecomment-322024199
	// Let's implicitly add in the respective keystore files
	// to avoid manually doing this step:
	// $ cp -r $GOPATH/src/github.com/tendermint/ethermint/setup/keystore $(DATADIR)
	keystoreDir := filepath.Join(ethermintDataDir, "keystore")
	if err := os.MkdirAll(keystoreDir, 0777); err != nil {
		ethUtils.Fatalf("mkdirAll keyStoreDir: %v", err)
	}

	for filename, content := range keystoreFilesMap {
		storeFileName := filepath.Join(keystoreDir, filename)
		f, err := os.Create(storeFileName)
		if err != nil {
			log.Error("create %q err: %v", storeFileName, err)
			continue
		}
		if _, err := f.Write([]byte(content)); err != nil {
			log.Error("write content %q err: %v", storeFileName, err)
		}
		if err := f.Close(); err != nil {
			return err
		}
	}

	return nil
}

var keystoreFilesMap = map[string]string{
	// https://github.com/tendermint/ethermint/blob/edc95f9d47ba1fb7c8161182533b5f5d5c5d619b/setup/keystore/UTC--2018-06-27T03-38-30.215306780Z--bc44a0962a82f89d660f5ccfa4fc1a51cce696ca
	// OR
	// $GOPATH/src/github.com/ethermint/setup/keystore/UTC--2018-06-27T03-38-30.215306780Z--bc44a0962a82f89d660f5ccfa4fc1a51cce696ca
	"UTC--2018-09-27T08-35-53.010502226Z--edac2dfcfe06f30920219221eccc79a300a8d7e1" : `
{"address":"edac2dfcfe06f30920219221eccc79a300a8d7e1","crypto":{"cipher":"aes-128-ctr","ciphertext":"7a3c22a5d84fba39588aa034e6e5f2862d3750ab004ee34ccfb2f114681cc718","cipherparams":{"iv":"0fcc20f0ead385d64b3b345cc0af0887"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"88d3875f792d6b2eed313677a2bf1c6e4b04e31c569700377d26877e973bd591"},"mac":"0f0c2bad80f367e9ef2618af8f19a1f229c0ec518a0a5dca1fe598f5a59969c5"},"id":"88dd147b-3a87-426d-932c-46040e20daf4","version":3}
`,
	"UTC--2018-09-27T08-35-53.813144295Z--4806202cd62b03be5f6681827d5329409c1e0cdd" : `
{"address":"4806202cd62b03be5f6681827d5329409c1e0cdd","crypto":{"cipher":"aes-128-ctr","ciphertext":"17c6f0fa0de813a70f0937695d849ffd866971e030a24c86841d03f2a190b9dd","cipherparams":{"iv":"22cec7099181031845967c4094494938"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"d20ca8b505f044af194345b8754f61b339f8394486192a22cf90b50c0acfff88"},"mac":"eeb5b360a9b84ca523e08420da04cd4fd6926ca2571b0a802cd48b5007c7d4d0"},"id":"13eb39b2-44f4-4b3d-8544-51ded01dbe70","version":3}
`,
	"UTC--2018-09-27T08-35-54.661872690Z--70ade99ba1966cab6584e90220b94154d4b58eb1" : `
{"address":"70ade99ba1966cab6584e90220b94154d4b58eb1","crypto":{"cipher":"aes-128-ctr","ciphertext":"ec5bfcb148dfd9264da41f915a3466d0f5e6ba6eeec3a1290311c4e989f4a583","cipherparams":{"iv":"bae1a7ca8fa77d92cc61cdba434aec72"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"37574cd0fbe8fb2f6802455802e19f9d8f12c402dc66f7964713e8b5d799dd4b"},"mac":"5ef686131ad3e8b6e86b3344bd92e291daf143a1405527f72dba85a41dfdf826"},"id":"9e5e38d4-8d46-41f2-aee0-6fd676fd8a73","version":3}
`,
	"UTC--2018-09-27T08-35-55.453699173Z--c2816eaf7e9804dc0804b6b33ab3e45b7d1f9823" : `
{"address":"c2816eaf7e9804dc0804b6b33ab3e45b7d1f9823","crypto":{"cipher":"aes-128-ctr","ciphertext":"73d30154dce5e8b0fe20b33194ce55636b2c32df0e9de40cb26551771da70a7d","cipherparams":{"iv":"76f871fc57ad46505155fbcefd61650f"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"5bad58bc95243db71225ac01c438730100a80f9f42554bf5e16c1e219930a4ad"},"mac":"cb40b62062ba01c0647e9f85793e89a532c6a508c97cab618c730a995389eb65"},"id":"7d1310a9-6dac-4948-a624-cb08d5d256d5","version":3}
`,
}

var privValidatorsMap = []string {
	`{"address":"271C3913A054A1C066155749261753D659F1D10B","pub_key":{"type":"ed25519","data":"745B6CA5FD60811129ABA521B42F0DFE3B27127EACC624E2294EBD5815B53428"},"last_height":0,"last_round":0,"last_step":0,"last_signature":null,"priv_key":{"type":"ed25519","data":"3223A79F064F06667A54A6AF1D0E8C62003373221E5515AED29F300DCA1E614C745B6CA5FD60811129ABA521B42F0DFE3B27127EACC624E2294EBD5815B53428"}}
	`,
	`{"address":"F21CD8EB717E4054A118357AAC158DF1A0888797","pub_key":{"type":"ed25519","data":"D9F477E36B5913A6520C6F4589883781CDCA068DFD58EE9E32FA59791ADFA4F5"},"last_height":0,"last_round":0,"last_step":0,"last_signature":null,"priv_key":{"type":"ed25519","data":"5D739A4BD2072467E433BACEBB8213B27D7DFDE8A32356A1C8521E6D06B9BD9CD9F477E36B5913A6520C6F4589883781CDCA068DFD58EE9E32FA59791ADFA4F5"}}
	`,
	`{"address":"49A3ABE0AA8C2DB2A9CD1BE92DE99E360C4DFD4C","pub_key":{"type":"ed25519","data":"EC0166D1877F7F0E2766FF2B59F18CAA259F11CAF89C943DDE2C8812842FCE2F"},"last_height":0,"last_round":0,"last_step":0,"last_signature":null,"priv_key":{"type":"ed25519","data":"C973BBE1E0E36F7DF69885BDBCD7DEB076145A5D6273DF21DB068FD51B1842BBEC0166D1877F7F0E2766FF2B59F18CAA259F11CAF89C943DDE2C8812842FCE2F"}}
	`,
	`{"address":"0D938238D7C64919BB9A6301534B62994230A9A0","pub_key":{"type":"ed25519","data":"8DF253737D59BFC7C4127B59412DE30E46EE9B886121954C8100DAFB81013972"},"last_height":0,"last_round":0,"last_step":0,"last_signature":null,"priv_key":{"type":"ed25519","data":"C769FCEA70A9DE33B21BCA0AC21C64B60700788EE51A7965E04A5C89463358728DF253737D59BFC7C4127B59412DE30E46EE9B886121954C8100DAFB81013972"}}
	`,
}

var defaultAccounts = []string {
	"0xedac2dfcfe06f30920219221eccc79a300a8d7e1",
	"0x4806202cd62b03be5f6681827d5329409c1e0cdd",
	"0x70ade99ba1966cab6584e90220b94154d4b58eb1",
	"0xc2816eaf7e9804dc0804b6b33ab3e45b7d1f9823",
}