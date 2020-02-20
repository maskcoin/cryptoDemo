package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
)

// des的CBC加密
// 编写填充函数，如果最后一个分组字节数不够，填充
// ......字节数刚好合适，添加一个新的分组
func paddingLastGroup(plainText []byte, blockSize int) []byte {
	// 1. 求出最后一个组中剩余的字节数
	padNum := blockSize - len(plainText)%blockSize
	// 2. 创建一个新的切片，长度 == padNum，每个字节值 byte(padNum)
	char := []byte{byte(padNum)}
	// 切片创建，并初始化
	newPlain := bytes.Repeat(char, padNum)
	// 3.newPlain数组追加到原始名文的后面
	plainText = append(plainText, newPlain...)
	return plainText
}

// 去掉填充的数据
func unPaddingLastGroup(plainText []byte) []byte {
	// 1.取出切片里面的最后一个字节
	length := len(plainText)
	lastChar := plainText[length-1]
	lastByteNumber := int(lastChar)
	return plainText[:length-lastByteNumber]
}

// des加密，cbc分组模式
func desEncrypt(plainText, key []byte) []byte  {
	//1.获得一个底层使用des的接口
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// 2. 明文填充
	newText := paddingLastGroup(plainText, block.BlockSize())
	// 3. 创建一个使用cbc分组的接口
	iv := []byte("12345678")
	blockMode := cipher.NewCBCEncrypter(block, iv)
	// 4.加密
	blockMode.CryptBlocks(newText, newText)
	return newText
}

// des解密
func desDecrypt(cipherText, key []byte) []byte {
	//1.获得一个底层使用des的接口
	block, err := des.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := []byte("12345678")
	blockMode := cipher.NewCBCDecrypter(block, iv)

	blockMode.CryptBlocks(cipherText, cipherText)
	return cipherText
}

// aes加密，ctr分组模式
func aesEncrypt(plainText, key []byte) []byte  {
	//1.获得一个底层使用aes的接口
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	// 3. 创建一个使用ctr分组的接口
	iv := []byte("1234567812345678")
	streamMode := cipher.NewCTR(block, iv)
	// 4.加密
	streamMode.XORKeyStream(plainText, plainText)
	return plainText
}

// aes解密
func aesDecrypt(cipherText, key []byte) []byte {
	//1.获得一个底层使用aes的接口
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	iv := []byte("1234567812345678")
	streamMode := cipher.NewCTR(block, iv)

	streamMode.XORKeyStream(cipherText, cipherText)
	return cipherText
}
