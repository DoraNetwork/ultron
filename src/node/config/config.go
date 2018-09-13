package config

import (
	"os"
	"path"
	"strings"

	"github.com/spf13/viper"

	"github.com/ethereum/go-ethereum/node"
	tmcfg "github.com/tendermint/tendermint/config"
	cmn "github.com/tendermint/tmlibs/common"
)

const (
	configFile        = "config.toml"
	defaultEthChainId = 188
)

var configContent	  = (*UltronConfig)(nil)
type UltronConfig struct {
	BaseConfig BaseConfig      `mapstructure:",squash"`
	TMConfig   tmcfg.Config    `mapstructure:",squash"`
	EMConfig   EthermintConfig `mapstructure:"vm"`
	TestConfig TConfig         `mapstructure:"test"`
}

func DefaultConfig() *UltronConfig {
	return &UltronConfig{
		BaseConfig: DefaultBaseConfig(),
		TMConfig:   *tmcfg.DefaultConfig(),
		EMConfig:   DefaultEthermintConfig(),
		TestConfig: DefaultTestConfig(),
	}
}

type BaseConfig struct {
	// The root directory for all data.
	// This should be set in viper so it can unmarshal into this struct
	RootDir string `mapstructure:"home"`
}

func DefaultBaseConfig() BaseConfig {
	return BaseConfig{}
}

type EthermintConfig struct {
	EthChainId        uint   `mapstructure:"eth_chain_id"`
	RootDir           string `mapstructure:"home"`
	ABCIAddr          string `mapstructure:"abci_laddr"`
	ABCIProtocol      string `mapstructure:"abci_protocol"`
	RPCEnabledFlag    bool   `mapstructure:"rpc"`
	RPCListenAddrFlag string `mapstructure:"rpcaddr"`
	RPCPortFlag       uint   `mapstructure:"rpcport"`
	RPCCORSDomainFlag string `mapstructure:"rpccorsdomain"`
	RPCApiFlag        string `mapstructure:"rpcapi"`
	WSEnabledFlag     bool   `mapstructure:"ws"`
	WSListenAddrFlag  string `mapstructure:"wsaddr"`
	WSPortFlag        uint   `mapstructure:"wsport"`
	WSApiFlag         string `mapstructure:"wsapi"`
	VerbosityFlag     uint   `mapstructure:"verbosity"`
}

type TConfig struct {
	RepeatTxTest           bool         `mapstructure:"repeat_tx_test"`
	TxSameAccount          bool         `mapstructure:"tx_same_account"`
	TxMultiAccount         bool         `mapstructure:"tx_multi_account"`
	RepeastSendSleep       uint         `mapstructure:"repeat_send_sleep"`
	ContractSameAccount    bool         `mapstructure:"contract_same_account"`
	ContractMultiAccount   bool         `mapstructure:"contract_multi_account"`
	PrintConsensusLog      bool         `mapstructure:"print_consensus_log"`
	PrintSendRecvLog       bool         `mapstructure:"print_sendrecv_log"`
	PrintPtxLog            bool         `mapstructure:"ptx_detail_log"`
	ForceValidator         bool         `mapstructure:"force_validator"`
	CompactBlock           bool         `mapstructure:"tm_compact_block"`
	BuildFullBlock         bool         `mapstructure:"build_full_block"`	// use compact block build full block
	UsePtxHash             bool         `mapstructure:"broadcast_ptx_hash"`	// broadcast ptx with hash or ptx with tx
	PtxCyclePeriod         uint         `mapstructure:"ptx_cycle_period"`
	DisablePtx             bool         `mapstructure:"disable_ptx"`
}

func DefaultEthermintConfig() EthermintConfig {
	return EthermintConfig{
		EthChainId:        defaultEthChainId,
		ABCIAddr:          "tcp://0.0.0.0:8848",
		ABCIProtocol:      "socket",
		RPCEnabledFlag:    true,
		RPCListenAddrFlag: node.DefaultHTTPHost,
		RPCPortFlag:       node.DefaultHTTPPort,
		RPCApiFlag:        "eth,net,web3,personal,admin",
		WSEnabledFlag:     true,
		WSListenAddrFlag:  node.DefaultWSHost,
		WSPortFlag:        node.DefaultWSPort,
		WSApiFlag:         "",
		VerbosityFlag:     3,
	}
}

func DefaultTestConfig() TConfig {
	return TConfig{
		RepeatTxTest:         false,
		TxSameAccount:        false,
		TxMultiAccount:       false,
		ContractSameAccount:  false,
		ContractMultiAccount: false,
	}
}

// ParseConfig retrieves the default environment configuration,
// sets up the Tendermint root and ensures that the root exists
func ParseConfig() (*UltronConfig, error) {
	if (configContent != nil) {
		return configContent, nil
	}
	conf := DefaultConfig()
	err := viper.Unmarshal(&conf)
	if err != nil {
		return nil, err
	}
	conf.TMConfig.SetRoot(conf.BaseConfig.RootDir)
	ensureRoot(conf.BaseConfig.RootDir)

	configContent = conf

	return conf, err
}

func ensureRoot(rootDir string) {
	if err := cmn.EnsureDir(rootDir, 0700); err != nil {
		cmn.PanicSanity(err.Error())
	}
	if err := cmn.EnsureDir(rootDir+"/data", 0700); err != nil {
		cmn.PanicSanity(err.Error())
	}

	configFilePath := path.Join(rootDir, configFile)

	// Write default config file if missing.
	if !cmn.FileExists(configFilePath) {
		cmn.MustWriteFile(configFilePath, []byte(defaultConfig(defaultMoniker)), 0644)
	}
}

func defaultConfig(moniker string) string {
	return strings.Replace(defaultConfigTmpl, "__MONIKER__", moniker, -1)
}

var defaultConfigTmpl = `
# This is a TOML config file.
# For more information, see https://github.com/toml-lang/toml

moniker = "__MONIKER__"
fast_sync = true
db_backend = "leveldb"
log_level = "state:info,*:error"

[rpc]
laddr = "tcp://0.0.0.0:46657"

[p2p]
laddr = "tcp://0.0.0.0:46656"
seeds = ""

[vm]
rpc = true
rpcapi = "eth,net,web3,personal,admin"
rpcaddr = "0.0.0.0"
rpcport = 8545
ws = false
verbosity = 1


[consensus]
timeout_commit = 10000
max_block_size_txs = 50000

[test]
repeat_tx_test = false
tx_multi_account = false
print_consensus_log = true
print_sendrecv_log = false
repeat_send_sleep = 0
ptx_detail_log = false
tm_compact_block = true
build_full_block = true
broadcast_ptx_hash = true
disable_ptx = true
ptx_cycle_period = 1100
force_validator = true
`

var defaultMoniker = getDefaultMoniker()

// getDefaultMoniker returns a default moniker, which is the host name. If runtime
// fails to get the host name, "anonymous" will be returned.
func getDefaultMoniker() string {
	moniker, err := os.Hostname()
	if err != nil {
		moniker = "anonymous"
	}
	return moniker

}
