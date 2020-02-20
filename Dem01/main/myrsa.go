package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// 生成rsa的密钥对，并且保存到磁盘文件中
func GenerateRsaKey(bits int) error {
	// 产生一个私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return err
	}
	// 把私钥序列化成二进制格式以便保存或发送
	der := x509.MarshalPKCS1PrivateKey(privateKey)

	// 对序列化好的二进制私钥进行一下包装
	// 要组织一个pem.Block
	block := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   der,
	}

	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	defer file.Close()

	// 把包装好的私钥写入到文件
	err = pem.Encode(file, block)
	if err != nil {
		return err
	}

	// ============= pulibc key==============
	// 把公钥序列化成二进制格式以便保存或发送
	derPub, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		fmt.Println("x509.MarshalPKIXPublicKey(privateKey.PublicKey) err=", err)
		return err
	}

	// 对序列化好的二进制私钥进行一下包装
	// 要组织一个pem.Block
	blockPub := &pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   derPub,
	}

	filePub, err := os.Create("public.pem")
	if err != nil {
		return err
	}
	defer filePub.Close()

	// 把包装好的公钥写入到文件
	err = pem.Encode(filePub, blockPub)
	if err != nil {
		return err
	}

	return err
}

// RSA加密
func RSAEncrypt(plainText []byte, pubKeyFileName string) ([]byte, error)  {
	// 1. 打开文件，并且读出文件内容
	file, err := os.Open(pubKeyFileName)
	if err != nil {
		fmt.Println("os.Open(pubKeyFileName) err=", err)
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("file.Stat() err=", err)
		return nil, err
	}

	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		fmt.Println("file.Read(buf) err=", err)
		return nil, err
	}

	//依次反向操作
	block, _ := pem.Decode(buf)
	if block == nil {
		fmt.Println("pem.Decode(buf) err")
		return nil, errors.New("pem.Decode(buf) err")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("x509.ParsePKIXPublicKey(bytes) err=", err)
		return nil, err
	}

	pubKey := pub.(*rsa.PublicKey)

	// 使用公钥加密
	cipherBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText)
	if err != nil {
		fmt.Println("rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText) err=", err)
		return nil, err
	}
	return cipherBytes, err
}

// RSA解密
func RSADecrypt(cipherText []byte, privateKeyFileName string) ([]byte, error)  {
	// 1. 打开文件，并且读出文件内容
	file, err := os.Open(privateKeyFileName)
	if err != nil {
		fmt.Println("os.Open(privateKeyFileName) err=", err)
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("file.Stat() err=", err)
		return nil, err
	}

	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		fmt.Println("file.Read(buf) err=", err)
		return nil, err
	}

	//依次反向操作
	block, _ := pem.Decode(buf)
	if block == nil {
		fmt.Println("pem.Decode(buf) err")
		return nil, errors.New("pem.Decode(buf) err")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("x509.ParsePKCS1PrivateKey(block.Bytes) err=", err)
		return nil, err
	}

	// 使用私钥解密
	plainBytes, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	if err != nil {
		fmt.Println("rsa.EncryptPKCS1v15(rand.Reader, pubKey, plainText) err=", err)
		return nil, err
	}
	return plainBytes, err
}

