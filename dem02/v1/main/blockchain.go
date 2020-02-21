package main

type BlockChain struct {
	//定义一个区块链切片
	blocks []*Block
}

func NewBlockChain() *BlockChain {
	genesisBlock := GenesisBlock()

	return &BlockChain{blocks: []*Block{genesisBlock}}
}

func (bc *BlockChain) AddBlock(data []byte) {
	lastBlock := bc.blocks[len(bc.blocks)-1]
	block := NewBlock(data, lastBlock.Hash)
	bc.blocks = append(bc.blocks, block)
}
