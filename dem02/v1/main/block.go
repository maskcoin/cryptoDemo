package main

import "crypto/sha256"

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

func GenesisBlock() *Block {
	return NewBlock([]byte("Genesis block"), nil)
}
