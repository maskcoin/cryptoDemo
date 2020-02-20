package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// 1. 生成密钥对
func GenerateEccKey() error  {
	// 产生一个私钥
	privateKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return err
	}

	// 把私钥序列化成二进制格式以便保存或发送
	der, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}

	// 对序列化好的二进制私钥进行一下包装
	// 要组织一个pem.Block
	block := &pem.Block{
		Type:    "ECC PRIVATE KEY",
		Headers: nil,
		Bytes:   der,
	}

	file, err := os.Create("eccPrivate.pem")
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
		Type:    "ECC PUBLIC KEY",
		Headers: nil,
		Bytes:   derPub,
	}

	filePub, err := os.Create("eccPublic.pem")
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

// ecc签名
func EccSignature(plainText []byte, privateKeyFileName string) (rBytes, sBytes []byte, err error)  {
	// 1. 打开文件，并且读出文件内容
	file, err := os.Open(privateKeyFileName)
	if err != nil {
		fmt.Println("os.Open(privateKeyFileName) err=", err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("file.Stat() err=", err)
		return
	}

	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		fmt.Println("file.Read(buf) err=", err)
		return
	}

	//依次反向操作
	block, _ := pem.Decode(buf)
	if block == nil {
		fmt.Println("pem.Decode(buf) err")
		err = errors.New("pem.Decode(buf) err")
		return
	}

	privateKey, err :=x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		fmt.Println("x509.ParsePKCS1PrivateKey(block.Bytes) err=", err)
		return
	}

	h := sha512.New()
	_, err = h.Write(plainText)
	if err != nil {
		fmt.Println("h.Write(plainText) err=", err)
		return
	}
	hashText := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hashText)
	if err != nil {
		fmt.Println("ecdsa.Sign(rand.Reader, privateKey, hashText) err=",err)
		return
	}

	rBytes, err = r.MarshalText()
	if err != nil {
		fmt.Println("r.MarshalText() err=",err)
		return
	}

	sBytes, err = s.MarshalText()
	if err != nil {
		fmt.Println("s.MarshalText() err=", err)
		return
	}
	return
}

// ecc认证
func ECCVerify(plainText, rBytes, sBytes []byte, pubKeyFileName string) error {
	// 1. 打开文件，并且读出文件内容
	file, err := os.Open(pubKeyFileName)
	if err != nil {
		fmt.Println("os.Open(pubKeyFileName) err=", err)
		return err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		fmt.Println("file.Stat() err=", err)
		return err
	}

	buf := make([]byte, fileInfo.Size())
	_, err = file.Read(buf)
	if err != nil {
		fmt.Println("file.Read(buf) err=", err)
		return err
	}

	//依次反向操作
	block, _ := pem.Decode(buf)
	if block == nil {
		fmt.Println("pem.Decode(buf) err")
		return errors.New("pem.Decode(buf) err")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		fmt.Println("x509.ParsePKIXPublicKey(bytes) err=", err)
		return err
	}

	pubKey := pub.(*ecdsa.PublicKey)
	h := sha512.New()
	_, err = h.Write(plainText)
	if err != nil {
		fmt.Println("h.Write(plainText) err=", err)
		return err
	}
	hashText := h.Sum(nil)

	var r, s big.Int
	r.UnmarshalText(rBytes)
	s.UnmarshalText(sBytes)
	if ecdsa.Verify(pubKey, hashText, &r, &s) == false {
		err = errors.New("ecdsa.Verify(pubKey, hashText, &r, &s)")
	}
	return err
}
