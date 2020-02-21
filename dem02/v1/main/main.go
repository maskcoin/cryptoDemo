package main

import (
	"crypto/sha256"
	"fmt"
)

type Block struct {
	PrevHash []byte
	Hash     []byte
	Data     []byte
}

func (block *Block) SetHash() {
	//1. 拼装数据
	blockInfo := append(block.PrevHash, block.Data...)
	//2. sha256
	hash := sha256.Sum256(blockInfo)
	block.Hash = hash[:]
}

func NewBlock(data, prevBlockHash []byte) *Block {
	block := &Block{
		PrevHash: prevBlockHash,
		Hash:     nil,
		Data:     data,
	}
	block.SetHash()
	return block
}

func main() {
	block := NewBlock([]byte("老师转班长一枚比特币！"), nil)
	fmt.Printf("前区块哈希值：%x\n", block.PrevHash)
	fmt.Printf("当前区块哈希值：%x\n", block.Hash)
	fmt.Printf("数据：%s\n", block.Data)
}
