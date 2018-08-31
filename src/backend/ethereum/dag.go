package ethereum

import (
	"github.com/ethereum/go-ethereum/common"
)

type VNode struct {
	Data interface{} //common.Hash
}

type Dag struct {
	Nodes [][]*VNode
}

func NewVNode(data interface{}) *VNode {
	return &VNode{
		Data: data,
	}
}

func NewDag(data [][]common.Hash) *Dag {
	var allNodes [][]*VNode
	for _, hashes := range data {
		var nodes []*VNode
		for _, hash := range hashes {
			// fmt.Println("put to dag", hash.Hex())
			nodes = append(nodes, NewVNode(hash.Bytes()))
		}
		allNodes = append(allNodes, nodes)
	}
	return &Dag{Nodes: allNodes}
}

// func NewDag(data [][]*VNode) *Dag {
// 	dag := &Dag{nodes: data}
// 	return dag
// }

func (this *Dag) Serialize() [][]common.Hash {
	var allHashes [][]common.Hash
	for _, nodes := range this.Nodes {
		var hashes []common.Hash
		for _, vnode := range nodes {
			hash := common.BytesToHash(vnode.Data.([]byte))
			// fmt.Println("hash", hash.Hex())
			hashes = append(hashes, hash)
		}
		allHashes = append(allHashes, hashes)
	}
	return allHashes
}
