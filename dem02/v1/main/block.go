package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"time"
)

type Block struct {
	Version    uint64
	PrevHash   []byte
	MerkelRoot []byte
	TimeStamp  uint64
	Difficulty uint64
	Nonce      uint64
	//当前区块哈希，正常比特币区块中没有当前区块的哈希
	Hash       []byte
	Data       []byte
}

//实现一个辅助函数，功能是讲uint64转成[]byte
func Uint64ToBytes(num uint64) []byte {
	var buffer bytes.Buffer
	err := binary.Write(&buffer, binary.BigEndian, num)
	if err != nil {
		panic(err)
	}
	return buffer.Bytes()
}

func (block *Block) SetHash() {
	//1. 拼装数据
	//var blockInfo []byte
	/*
	blockInfo = append(blockInfo, Uint64ToBytes(block.Version)...)
	blockInfo = append(blockInfo, block.PrevHash...)
	blockInfo = append(blockInfo, block.MerkelRoot...)
	blockInfo = append(blockInfo, Uint64ToBytes(block.TimeStamp)...)
	blockInfo = append(blockInfo, Uint64ToBytes(block.Difficulty)...)
	blockInfo = append(blockInfo, Uint64ToBytes(block.Nonce)...)
	blockInfo = append(blockInfo, block.Data...)
	*/
	blockInfo := bytes.Join([][]byte{
		Uint64ToBytes(block.Version),
		block.PrevHash,
		block.MerkelRoot,
		Uint64ToBytes(block.TimeStamp),
		Uint64ToBytes(block.Difficulty),
		Uint64ToBytes(block.Nonce),
		block.Data,
	}, nil)

	//2. sha256
	hash := sha256.Sum256(blockInfo)
	block.Hash = hash[:]
}

func NewBlock(data, prevBlockHash []byte) *Block {
	block := &Block{
		Version:    0,
		PrevHash:   prevBlockHash,
		MerkelRoot: nil,
		TimeStamp:  uint64(time.Now().Unix()),
		Difficulty: 0,
		Nonce:      0,
		Hash:       nil,
		Data:       data,
	}
	block.SetHash()
	return block
}

func GenesisBlock() *Block {
	return NewBlock([]byte("Genesis block"), nil)
}
