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
			Address:   "0x0413c6cc6d4381489815b35118f6fa3a1d45a3f9",
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
	"UTC--2018-07-31T09-46-32.152086103Z--0413c6cc6d4381489815b35118f6fa3a1d45a3f9" : `
{"address":"0413c6cc6d4381489815b35118f6fa3a1d45a3f9","crypto":{"cipher":"aes-128-ctr","ciphertext":"dc14ea2348c19dbb27bf3933b0940630db1722a439cdb7674a4b45293f16276b","cipherparams":{"iv":"e777ea653776b054e119a6b6a1a884ae"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":1024,"p":1,"r":8,"salt":"ab2cba64075ee94f9388352719089e9f80af2bcdaec2b05aad681f79c0267645"},"mac":"1bedea894f5f1fa0f820fe144f89f7507e14192f931d627bf1d84dd41494d54a"},"id":"7b31477e-fe2e-4546-b1a9-2b9ec2f58e9c","version":3}
`,
	"UTC--2018-07-31T09-46-31.351271325Z--cd89dde88bc4e308e436f9f696454840ff795d84" : `
{"address":"cd89dde88bc4e308e436f9f696454840ff795d84","crypto":{"cipher":"aes-128-ctr","ciphertext":"90406e8f2884669475f7eab62c0d5e18d52093bc3ab5130b5ef95a21bcb3406e","cipherparams":{"iv":"7f926d377d84436348492dc21ae1e849"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":1024,"p":1,"r":8,"salt":"3fe457439bd22254b092435290ba2c14df81ae848ae102a07210f068f93a0194"},"mac":"ec066f38a399810619e699e042f8fc3a7c6cd5104729fffa0cd47935991e4963"},"id":"1d1919fb-d0da-4735-a46b-364d9f2ff795","version":3}
`,
	"UTC--2018-08-06T06-13-36.205357854Z--1780858a3eb6f491adb0b30cc5218746b5f9442c" : `
{"address":"1780858a3eb6f491adb0b30cc5218746b5f9442c","crypto":{"cipher":"aes-128-ctr","ciphertext":"1d328ce29f48c03a132643458c7a87a744fef08c4a116a4c552938bffc377430","cipherparams":{"iv":"dfd0e627eaa5da9b3f3ed4f4a5431389"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":1024,"p":1,"r":8,"salt":"5ed52231de773ac95c1eadc4e609cc10cf2240215c040a792d60e91bc0c26714"},"mac":"0664d5a6570fc8644b63123c6c92c21e0689f7aaa0d3697a185a659c99ef36f0"},"id":"9c12c360-d73c-47f8-ab19-6ad5efee7a64","version":3}
`,
	"UTC--2018-08-06T06-13-36.238372425Z--fa5787ff486c4093a2f6b6708d28e8e8da6d7957" : `
{"address":"fa5787ff486c4093a2f6b6708d28e8e8da6d7957","crypto":{"cipher":"aes-128-ctr","ciphertext":"4e7e3d0d90e96bb1ca1600d3c79fbfd8ac4564a0d581210b4494033a5611d541","cipherparams":{"iv":"839c485eb6e82d4b7cf4be3de42846dc"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":1024,"p":1,"r":8,"salt":"4a85719fb7bc5df8657a91cfc78dfddb5fe93365d2edc887fa4e56e5a5fc6e83"},"mac":"122f069e4c7a2d52360e5e233d9e500d981f062ba7cc06de3c2053150f2af70e"},"id":"91e40c46-14d0-4a3d-8353-d4b2061acc48","version":3}
`,
	"UTC--2018-08-06T06-13-34.299989499Z--c6fc3cfcfd5b8c6ffa8d0b77f8611f001b79717b" : `
{"address":"c6fc3cfcfd5b8c6ffa8d0b77f8611f001b79717b","crypto":{"cipher":"aes-128-ctr","ciphertext":"4672f5dae172f9cc450181cffb218ae4a2682ff0e60d26725a59120f0e094ed4","cipherparams":{"iv":"51f8c4894b7c8e955264d1f586e14d57"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":1024,"p":1,"r":8,"salt":"105607289fe24d2727758b24098ec82b95e2b67077f0cd003d372a2f51c16b1c"},"mac":"1b2fcbd72761eb6fa44cddc8d23bb87f4be20de0bee606a528af7ad9afb95498"},"id":"dcc498c8-a847-4ee8-b4d9-cb22186bc6d5","version":3}
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
	`{"address":"27FAECDC50542E16736579B3B713C5F8D96232BE","pub_key":{"type":"ed25519","data":"110E5739E5729043ECD6E302ABC31DD6D0D703A1C7A46C359E60E617CE55B411"},"last_height":0,"last_round":0,"last_step":0,"last_signature":null,"priv_key":{"type":"ed25519","data":"A605984972D049F991A170625128CA379B418DA56AB6AC161AB0C39B511C6812110E5739E5729043ECD6E302ABC31DD6D0D703A1C7A46C359E60E617CE55B411"}}
	`,
}

var defaultAccounts = []string {
	"0x0413c6cc6d4381489815b35118f6fa3a1d45a3f9",
	"0x1780858a3eb6f491adb0b30cc5218746b5f9442c",
	"0xfa5787ff486c4093a2f6b6708d28e8e8da6d7957",
	"0xc6fc3cfcfd5b8c6ffa8d0b77f8611f001b79717b",
	"0xcd89dde88bc4e308e436f9f696454840ff795d84",
}