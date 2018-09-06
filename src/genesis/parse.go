package genesis

import (
	"encoding/json"

	"github.com/cosmos/cosmos-sdk"
	"github.com/pkg/errors"

	cmn "github.com/tendermint/tmlibs/common"
	"strconv"

	"github.com/dora/ultron/const"
)

// KeyDelimiter is used to separate module and key in
// the options
const KeyDelimiter = "/"

// Option just holds module/key/value triples from
// parsing the genesis file
type Option struct {
	Module string
	Key    string
	Value  string
}

// InitStater is anything that can handle app options
// from genesis file. Setting the merkle store, config options,
// or anything else
type InitStater interface {
	InitState(module, key, value string) error
}

// Load parses the genesis file and sets the initial
// state based on that
func Load(app InitStater, filePath string) error {
	opts, err := GetOptions(filePath)
	if err != nil {
		return err
	}

	// execute all the genesis init options
	// abort on any error
	for _, opt := range opts {
		err = app.InitState(opt.Module, opt.Key, opt.Value)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetOptions parses the genesis file in a format
// that can easily be handed into InitStaters
func GetOptions(path string) ([]Option, error) {
	genDoc, err := load(path)
	if err != nil {
		return nil, err
	}

	//opts := genDoc.AppOptions
	validators := genDoc.Validators
	cnt := 3 + len(validators)
	res := make([]Option, 0, cnt)
	res = append(res, Option{sdk.ModuleNameBase, sdk.ChainKey, genDoc.ChainID})
	res = append(res, Option{constant.ModuleNameStake, "max_vals", strconv.Itoa(int(genDoc.MaxVals))})
	res = append(res, Option{constant.ModuleNameStake, "reserve_requirement_ratio", genDoc.ReserveRequirementRatio})

	// set validators
	for _, val := range validators {
		res = append(res, Option{constant.ModuleNameStake, "validator", string(val)})
	}

	return res, nil
}

type keyValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// FullDoc - includes tendermint (in the json, we ignore here)
type FullDoc struct {
	ChainID                 string            `json:"chain_id"`
	AppOptions              *Doc              `json:"app_options"`
	Validators              []json.RawMessage `json:"validators"`
	MaxVals                 uint16            `json:"max_vals"`
	ReserveRequirementRatio string            `json:"reserve_requirement_ratio"`
}

// Doc - All genesis values
type Doc struct {
	Accounts []json.RawMessage `json:"accounts"`
}

func load(filePath string) (*FullDoc, error) {
	bytes, err := cmn.ReadFile(filePath)
	if err != nil {
		return nil, errors.Wrap(err, "loading genesis file")
	}

	// the basecoin genesis go-wire/data :)
	genDoc := new(FullDoc)
	err = json.Unmarshal(bytes, genDoc)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling genesis file")
	}

	if genDoc.AppOptions == nil {
		genDoc.AppOptions = new(Doc)
	}

	return genDoc, nil
}
