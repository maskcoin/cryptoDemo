package main

import "fmt"

type Block struct {
	PrevHash []byte
	Hash []byte
	Data []byte
}

func NewBlock(data, prevBlockHash []byte ) *Block  {
	block := &Block{
		PrevHash: prevBlockHash,
		Hash:     nil, //TODO
		Data:     data,
	}
	return block
}

func main() {
	block := NewBlock([]byte("老师转班长一枚比特币！"), nil)
	fmt.Printf("前区块哈希值：%x\n", block.PrevHash)
	fmt.Printf("当前区块哈希值：%x\n", block.Hash)
	fmt.Printf("数据：%s\n", block.Data)
}
