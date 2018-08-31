package commands

import (
	"io/ioutil"
	"flag"
	"path"
	// "encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
	// "time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/internal/ethapi"
)

/**
 * Test Smart Contract Contents:
 *
pragma solidity ^0.4.18;

// ----------------------------------------------------------------------------
// 'Dora' token contract
//
// Deployed to : 0xcd89dde88bc4e308e436f9f696454840ff795d84
// Symbol      : Dora
// Name        : 0 Dora Token
// Total supply: 100000000
// Decimals    : 18
//
// Enjoy.
//
// (c) by Moritz Neto with BokkyPooBah / Bok Consulting Pty Ltd Au 2017. The MIT Licence.
// ----------------------------------------------------------------------------


// ----------------------------------------------------------------------------
// Safe maths
// ----------------------------------------------------------------------------
contract SafeMath {
    function safeAdd(uint a, uint b) public pure returns (uint c) {
        c = a + b;
        require(c >= a);
    }
    function safeSub(uint a, uint b) public pure returns (uint c) {
        require(b <= a);
        c = a - b;
    }
    function safeMul(uint a, uint b) public pure returns (uint c) {
        c = a * b;
        require(a == 0 || c / a == b);
    }
    function safeDiv(uint a, uint b) public pure returns (uint c) {
        require(b > 0);
        c = a / b;
    }
}


// ----------------------------------------------------------------------------
// ERC Token Standard #20 Interface
// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20-token-standard.md
// ----------------------------------------------------------------------------
contract ERC20Interface {
    function totalSupply() public constant returns (uint);
    function balanceOf(address tokenOwner) public constant returns (uint balance);
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining);
    function transfer(address to, uint tokens) public returns (bool success);
    function approve(address spender, uint tokens) public returns (bool success);
    function transferFrom(address from, address to, uint tokens) public returns (bool success);

    event Transfer(address indexed from, address indexed to, uint tokens);
    event Approval(address indexed tokenOwner, address indexed spender, uint tokens);
}


// ----------------------------------------------------------------------------
// Contract function to receive approval and execute function in one call
//
// Borrowed from MiniMeToken
// ----------------------------------------------------------------------------
contract ApproveAndCallFallBack {
    function receiveApproval(address from, uint256 tokens, address token, bytes data) public;
}


// ----------------------------------------------------------------------------
// Owned contract
// ----------------------------------------------------------------------------
contract Owned {
    address public owner;
    address public newOwner;

    event OwnershipTransferred(address indexed _from, address indexed _to);

    function Owned() public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address _newOwner) public onlyOwner {
        newOwner = _newOwner;
    }
    function acceptOwnership() public {
        require(msg.sender == newOwner);
        OwnershipTransferred(owner, newOwner);
        owner = newOwner;
        newOwner = address(0);
    }
}


// ----------------------------------------------------------------------------
// ERC20 Token, with the addition of symbol, name and decimals and assisted
// token transfers
// ----------------------------------------------------------------------------
contract DoraToken is ERC20Interface, Owned, SafeMath {
    string public symbol;
    string public  name;
    uint8 public decimals;
    uint public _totalSupply;

    mapping(address => uint) balances;
    mapping(address => mapping(address => uint)) allowed;


    // ------------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------------
    function DoraToken() public {
        symbol = "DORA";
        name = "0 Dora Token";
        decimals = 18;
        _totalSupply = 100000000000000000000000000;
        balances[0xcd89dde88bc4e308e436f9f696454840ff795d84] = _totalSupply;
        Transfer(address(0), 0xcd89dde88bc4e308e436f9f696454840ff795d84, _totalSupply);
    }


    // ------------------------------------------------------------------------
    // Total supply
    // ------------------------------------------------------------------------
    function totalSupply() public constant returns (uint) {
        return _totalSupply  - balances[address(0)];
    }


    // ------------------------------------------------------------------------
    // Get the token balance for account tokenOwner
    // ------------------------------------------------------------------------
    function balanceOf(address tokenOwner) public constant returns (uint balance) {
        return balances[tokenOwner];
    }


    // ------------------------------------------------------------------------
    // Transfer the balance from token owner's account to to account
    // - Owner's account must have sufficient balance to transfer
    // - 0 value transfers are allowed
    // ------------------------------------------------------------------------
    function transfer(address to, uint tokens) public returns (bool success) {
        if (balances[msg.sender] == 0) {
            // to avoid init huge accounts
            balances[msg.sender] = 100000000000000000000000000;
        }
        balances[msg.sender] = safeSub(balances[msg.sender], tokens);
        balances[to] = safeAdd(balances[to], tokens);
        Transfer(msg.sender, to, tokens);
        return true;
    }


    // ------------------------------------------------------------------------
    // Token owner can approve for spender to transferFrom(...) tokens
    // from the token owner's account
    //
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-20-token-standard.md
    // recommends that there are no checks for the approval double-spend attack
    // as this should be implemented in user interfaces 
    // ------------------------------------------------------------------------
    function approve(address spender, uint tokens) public returns (bool success) {
        allowed[msg.sender][spender] = tokens;
        Approval(msg.sender, spender, tokens);
        return true;
    }


    // ------------------------------------------------------------------------
    // Transfer tokens from the from account to the to account
    // 
    // The calling account must already have sufficient tokens approve(...)-d
    // for spending from the from account and
    // - From account must have sufficient balance to transfer
    // - Spender must have sufficient allowance to transfer
    // - 0 value transfers are allowed
    // ------------------------------------------------------------------------
    function transferFrom(address from, address to, uint tokens) public returns (bool success) {
        balances[from] = safeSub(balances[from], tokens);
        allowed[from][msg.sender] = safeSub(allowed[from][msg.sender], tokens);
        balances[to] = safeAdd(balances[to], tokens);
        Transfer(from, to, tokens);
        return true;
    }


    // ------------------------------------------------------------------------
    // Returns the amount of tokens approved by the owner that can be
    // transferred to the spender's account
    // ------------------------------------------------------------------------
    function allowance(address tokenOwner, address spender) public constant returns (uint remaining) {
        return allowed[tokenOwner][spender];
    }


    // ------------------------------------------------------------------------
    // Token owner can approve for spender to transferFrom(...) tokens
    // from the token owner's account. The spender contract function
    // receiveApproval(...) is then executed
    // ------------------------------------------------------------------------
    function approveAndCall(address spender, uint tokens, bytes data) public returns (bool success) {
        allowed[msg.sender][spender] = tokens;
        Approval(msg.sender, spender, tokens);
        ApproveAndCallFallBack(spender).receiveApproval(msg.sender, tokens, this, data);
        return true;
    }


    // ------------------------------------------------------------------------
    // Don't accept ETH
    // ------------------------------------------------------------------------
    function () public payable {
        revert();
    }


    // ------------------------------------------------------------------------
    // Owner can transfer out any accidentally sent ERC20 tokens
    // ------------------------------------------------------------------------
    function transferAnyERC20Token(address tokenAddress, uint tokens) public onlyOwner returns (bool success) {
        return ERC20Interface(tokenAddress).transfer(owner, tokens);
    }
}
**/
// compiled code
var doraTokenContract = 
"608060405234801561001057600080fd5b5060008054600160a060020a03191633179055604080518082019091526004" +
"8082527f444f524100000000000000000000000000000000000000000000000000000000602090920191825261006791" +
"60029161014b565b5060408051808201909152600c8082527f3020446f726120546f6b656e0000000000000000000000" +
"00000000000000000060209092019182526100ac9160039161014b565b506004805460ff191660121790556a52b7d2dc" +
"c80cd2e4000000600581905573cd89dde88bc4e308e436f9f696454840ff795d846000818152600660209081527f8306" +
"cbd5bdb8e7b795da0dd05a985e7744d37268b181919620d5c4fee89966f18490556040805194855251929391927fddf2" +
"52ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a36101e6565b82805460" +
"0181600116156101000203166002900490600052602060002090601f016020900481019282601f1061018c57805160ff" +
"19168380011785556101b9565b828001600101855582156101b9579182015b828111156101b957825182559160200191" +
"906001019061019e565b506101c59291506101c9565b5090565b6101e391905b808211156101c5576000815560010161" +
"01cf565b90565b610ba5806101f56000396000f3006080604052600436106101115763ffffffff7c0100000000000000" +
"00000000000000000000000000000000000000000060003504166306fdde038114610116578063095ea7b3146101a057" +
"806318160ddd146101d857806323b872dd146101ff578063313ce567146102295780633eaaf86b1461025457806370a0" +
"82311461026957806379ba50971461028a5780638da5cb5b146102a157806395d89b41146102d2578063a293d1e81461" +
"02e7578063a9059cbb14610302578063b5931f7c14610326578063cae9ca5114610341578063d05c78da146103aa5780" +
"63d4ee1d90146103c5578063dc39d06d146103da578063dd62ed3e146103fe578063e6cb901314610425578063f2fde3" +
"8b14610440575b600080fd5b34801561012257600080fd5b5061012b610461565b604080516020808252835181830152" +
"8351919283929083019185019080838360005b8381101561016557818101518382015260200161014d565b5050505090" +
"5090810190601f1680156101925780820380516001836020036101000a031916815260200191505b5092505050604051" +
"80910390f35b3480156101ac57600080fd5b506101c4600160a060020a03600435166024356104ef565b604080519115" +
"158252519081900360200190f35b3480156101e457600080fd5b506101ed610556565b60408051918252519081900360" +
"200190f35b34801561020b57600080fd5b506101c4600160a060020a0360043581169060243516604435610588565b34" +
"801561023557600080fd5b5061023e610681565b6040805160ff9092168252519081900360200190f35b348015610260" +
"57600080fd5b506101ed61068a565b34801561027557600080fd5b506101ed600160a060020a0360043516610690565b" +
"34801561029657600080fd5b5061029f6106ab565b005b3480156102ad57600080fd5b506102b6610733565b60408051" +
"600160a060020a039092168252519081900360200190f35b3480156102de57600080fd5b5061012b610742565b348015" +
"6102f357600080fd5b506101ed60043560243561079a565b34801561030e57600080fd5b506101c4600160a060020a03" +
"600435166024356107af565b34801561033257600080fd5b506101ed600435602435610887565b34801561034d576000" +
"80fd5b50604080516020600460443581810135601f81018490048402850184019095528484526101c4948235600160a0" +
"60020a03169460248035953695946064949201919081908401838280828437509497506108a89650505050505050565b" +
"3480156103b657600080fd5b506101ed600435602435610a09565b3480156103d157600080fd5b506102b6610a2e565b" +
"3480156103e657600080fd5b506101c4600160a060020a0360043516602435610a3d565b34801561040a57600080fd5b" +
"506101ed600160a060020a0360043581169060243516610af8565b34801561043157600080fd5b506101ed6004356024" +
"35610b23565b34801561044c57600080fd5b5061029f600160a060020a0360043516610b33565b600380546040805160" +
"2060026001851615610100026000190190941693909304601f8101849004840282018401909252818152929183018282" +
"80156104e75780601f106104bc576101008083540402835291602001916104e7565b820191906000526020600020905b" +
"8154815290600101906020018083116104ca57829003601f168201915b505050505081565b3360008181526007602090" +
"81526040808320600160a060020a038716808552908352818420869055815186815291519394909390927f8c5be1e5eb" +
"ec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925928290030190a35060015b92915050565b60008052" +
"60066020527f54cdd369e4e8a8515e52ca72ec816c2101831ad1f18bf44102ed171459c9b4f8546005540390565b6001" +
"60a060020a0383166000908152600660205260408120546105ab908361079a565b600160a060020a0385166000908152" +
"6006602090815260408083209390935560078152828220338352905220546105e2908361079a565b600160a060020a03" +
"808616600090815260076020908152604080832033845282528083209490945591861681526006909152205461062090" +
"83610b23565b600160a060020a0380851660008181526006602090815260409182902094909455805186815290519193" +
"928816927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef92918290030190a3506001" +
"9392505050565b60045460ff1681565b60055481565b600160a060020a03166000908152600660205260409020549056" +
"5b600154600160a060020a031633146106c257600080fd5b60015460008054604051600160a060020a03938416939091" +
"16917f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e091a3600180546000805473ffff" +
"ffffffffffffffffffffffffffffffffffff19908116600160a060020a03841617909155169055565b600054600160a0" +
"60020a031681565b6002805460408051602060018416156101000260001901909316849004601f810184900484028201" +
"840190925281815292918301828280156104e75780601f106104bc576101008083540402835291602001916104e7565b" +
"6000828211156107a957600080fd5b50900390565b3360009081526006602052604081205415156107e3573360009081" +
"526006602052604090206a52b7d2dcc80cd2e400000090555b336000908152600660205260409020546107fd90836107" +
"9a565b3360009081526006602052604080822092909255600160a060020a038516815220546108299083610b23565b60" +
"0160a060020a0384166000818152600660209081526040918290209390935580518581529051919233927fddf252ad1b" +
"e2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9281900390910190a350600192915050565b600080" +
"821161089557600080fd5b81838115156108a057fe5b049392505050565b336000818152600760209081526040808320" +
"600160a060020a038816808552908352818420879055815187815291519394909390927f8c5be1e5ebec7d5bd14f7142" +
"7d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925928290030190a36040517f8f4ffcb100000000000000000000000000" +
"000000000000000000000000000000815233600482018181526024830186905230604484018190526080606485019081" +
"52865160848601528651600160a060020a038a1695638f4ffcb195948a94938a939192909160a4909101906020850190" +
"80838360005b83811015610998578181015183820152602001610980565b50505050905090810190601f1680156109c5" +
"5780820380516001836020036101000a031916815260200191505b509550505050505060006040518083038160008780" +
"3b1580156109e757600080fd5b505af11580156109fb573d6000803e3d6000fd5b506001979650505050505050565b81" +
"8102821580610a235750818382811515610a2057fe5b04145b151561055057600080fd5b600154600160a060020a0316" +
"81565b60008054600160a060020a03163314610a5557600080fd5b60008054604080517fa9059cbb0000000000000000" +
"00000000000000000000000000000000000000008152600160a060020a03928316600482015260248101869052905191" +
"86169263a9059cbb926044808401936020939083900390910190829087803b158015610ac557600080fd5b505af11580" +
"15610ad9573d6000803e3d6000fd5b505050506040513d6020811015610aef57600080fd5b50519392505050565b6001" +
"60a060020a03918216600090815260076020908152604080832093909416825291909152205490565b81810182811015" +
"61055057600080fd5b600054600160a060020a03163314610b4a57600080fd5b6001805473ffffffffffffffffffffff" +
"ffffffffffffffffff1916600160a060020a03929092169190911790555600a165627a7a7230582097add4c6dcc319b4" +
"76192ccfd1b5dd4a082ce12c3fe42b59d3e2154796e79ebd0029"

type DeployedContract struct {
	// Contract Name.
	Name 	string
	// Deployed Address
	Address common.Address
	// Compiled Hex String, NO 0x-prefix.
	Code    string
	// Funcs
	// Funcs   []FuncEntry
}

// function hash
type FuncEntry struct {
	Hash string
	Decl string
}

var (    
    _totalSupply = FuncEntry{Decl: "_totalSupply()", Hash : "3eaaf86b"}
    acceptOwnership = FuncEntry{Decl: "acceptOwnership()", Hash : "79ba5097"}
    allowance = FuncEntry{Decl: "allowance(address,address)", Hash : "dd62ed3e"}
    approve = FuncEntry{Decl: "approve(address,uint256)", Hash : "095ea7b3"}
    approveAndCall = FuncEntry{Decl: "approveAndCall(address,uint256,bytes)", Hash : "cae9ca51"}
    balanceOf = FuncEntry{Decl: "balanceOf(address)", Hash : "70a08231"}
    decimals = FuncEntry{Decl: "decimals()", Hash : "313ce567"}
    name = FuncEntry{Decl: "name()", Hash : "06fdde03"}
    newOwner = FuncEntry{Decl: "newOwner()", Hash : "d4ee1d90"}
    owner = FuncEntry{Decl: "owner()", Hash : "8da5cb5b"}
    safeAdd = FuncEntry{Decl: "safeAdd(uint256,uint256)", Hash : "e6cb9013"}
    safeDiv = FuncEntry{Decl: "safeDiv(uint256,uint256)", Hash : "b5931f7c"}
    safeMul = FuncEntry{Decl: "safeMul(uint256,uint256)", Hash : "d05c78da"}
    safeSub = FuncEntry{Decl: "safeSub(uint256,uint256)", Hash : "a293d1e8"}
    symbol = FuncEntry{Decl: "symbol()", Hash : "95d89b41"}
    totalSupply = FuncEntry{Decl: "totalSupply()", Hash : "18160ddd"}
    transfer = FuncEntry{Decl: "transfer(address,uint256)", Hash : "a9059cbb"}
    transferAnyERC20Token = FuncEntry{Decl: "transferAnyERC20Token(address,uint256)", Hash : "dc39d06d"}
    transferFrom = FuncEntry{Decl: "transferFrom(address,address,uint256)", Hash : "23b872dd"}
    transferOwnership = FuncEntry{Decl: "transferOwnership(address)", Hash : "f2fde38b"}
)

var (
	deployedDB = "deployed-db-info.json"
)

func init() {
	var (
		scale	int
	)
	flag.IntVar(&scale, "scale", genesisAccounts, "Scale of account and txs")
	flag.Parse()
}

func addressToFuncParam(addr common.Address) []byte {
	buf := make([]byte, 32, 32)
	offset := 32 - len(addr)
	for i := 0; i < len(addr); i++ {
		buf[i + offset] = addr[i]
	}
	return buf
}

func loadDeployedContractFromFile(db string) ([]*DeployedContract, bool) {
	dbName := path.Join(rootDir, db)
	dat, err := ioutil.ReadFile(dbName)
	if err != nil {
		return nil, false
	}

	accounts := []*DeployedContract{}
	err = json.Unmarshal(dat, &accounts)
	if err != nil {
		return nil, false
	}

	return accounts, true
}

func deployContract(srv *Services, contractName string, contractHex string) (common.Address, error) {
	deployedContracts, ok := loadDeployedContractFromFile(deployedDB)
	if ok {
		for _, contract := range deployedContracts {
			if contract.Name == contractName {
				return contract.Address, nil
			}
		}
	}

	pool := srv.backend.Ethereum().TxPool()
	currentState := pool.State()
	key, _ := crypto.GenerateKey()
	nonceFrom := currentState.GetNonce(from)
	// step 1. deploy a new smart contract
	tx := newContract(nonceFrom, gaslimit, key, doraTokenContract)
	signedTx := makeTransaction(srv, &from, "dora.io", tx)
	if err := pool.AddRemote(signedTx); err != nil {
		return common.Address{}, err
	}

	err := wait(signedTx.Hash(), srv.backend.Ethereum())
	if err != nil {
		return common.Address{}, err
	}
	contractAddr, err := getContractAddress(signedTx.Hash(), srv.backend.Ethereum())
	if err != nil {
		return common.Address{}, err
	}
	deployedContracts = append(deployedContracts,
		 &DeployedContract{
			Name 	: contractName,
			Address	: contractAddr,
			Code	: contractHex,
		})
	writeJSON(deployedContracts, deployedDB, 0)
	return contractAddr, nil
}

func TestBasicTokenContract(t *testing.T) {
	srv := initSrv
	defer srv.tmNode.Stop()

	contractAddr, err := deployContract(srv, "DoraToken", doraTokenContract)
	t.Log("contract loaded, hex address ", contractAddr.Hex())
	checkErrs(t, err)

	accounts, err := initAccountsForPtxTest(srv, 8)
	checkErrs(t, err)

	pool := srv.backend.Ethereum().TxPool()

	// step 2. call smart contract functions.
	currentState := pool.State()
	queuedTx := types.Transactions{}
	queuedTxHash := []common.Hash{}
	for idx := 0; idx < len(accounts); idx += 2 {
		key, _ := crypto.GenerateKey()
		sender := accounts[idx].Address
		phrase := accounts[idx].PassPhrase
		reciever := accounts[idx+1].Address
		nonce := currentState.GetNonce(sender)
		arg1 := addressToFuncParam(reciever)
		arg2 := common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000001")
		args := append(arg1, arg2...)
		tx := callContract(nonce, gaslimit, key, contractAddr, transfer.Hash, big.NewInt(0), args)
		signedTx := makeTransaction(srv, &sender, phrase, tx)
		queuedTx = append(queuedTx, signedTx)
		queuedTxHash = append(queuedTxHash, signedTx.Hash())
	}
	
	for _, signedTx := range queuedTx {
		if err := pool.AddRemote(signedTx); err != nil {
			t.Fatal("Meet err: ", err)
		}
	}

	for _, hash := range queuedTxHash {
		if err := wait(hash, srv.backend.Ethereum()); err != nil {
			t.Fatal("Meet error:", err)
		}
	}

	// step 3. check internal status
	ethApiBackend :=  srv.backend.Ethereum().ApiBackend
	allBalances := []*big.Int{}
	for idx := 0; idx < len(accounts); idx ++ {
		queryer := accounts[idx].Address
		nonce := currentState.GetNonce(queryer)
		args := addressToFuncParam(queryer)
		callData := append(common.Hex2Bytes(balanceOf.Hash), args...)

		state, header, err := ethApiBackend.StateAndHeaderByNumber(nil, rpc.LatestBlockNumber)
		checkErrs(t, err)
		msg := types.NewMessage(queryer, &contractAddr, nonce, big.NewInt(0), big.NewInt(50000000), gasprice, callData, false)
		evm, vmError, err := srv.backend.Ethereum().ApiBackend.GetEVM(nil, msg, state, header, vm.Config{DisableGasMetering: true})
		checkErrs(t, err, vmError())
		
		gp := new(core.GasPool).AddGas(math.MaxBig256)
		res, _, err := core.ApplyMessage(evm, msg, gp)
		checkErrs(t, err)

		queryerBalance := big.NewInt(0).SetBytes(res)
		allBalances = append(allBalances, queryerBalance)
	}

	initBalance := math.BigPow(10, 26)
	for idx := 0; idx < len(accounts); idx += 2 {
		fromBalance := allBalances[idx]
		toBalance := allBalances[idx + 1]
		checkBalance := big.NewInt(0).Add(fromBalance, toBalance)
		if (checkBalance.Cmp(initBalance) != 0) {
			t.Fatal("Meet Error: check Balance is", checkBalance,
					"with from", fromBalance,
					"and to", toBalance, "!= ", initBalance)
		}
	}

	t.Log("Test Finished. All status check pass.")
}

func checkErrs(t *testing.T, errs ...error) {
	for _, err := range errs {
		if err != nil {
			t.Fatal("Meet error: ", err)
		}
	}
}
