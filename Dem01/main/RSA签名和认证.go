package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// RSA签名
func SignatureRSA(plainText []byte, privateKeyFileName string) ([]byte, error)  {
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

	h := sha512.New()
	_, err = h.Write(plainText)
	if err != nil {
		fmt.Println("h.Write(plainText) err=", err)
		return nil, err
	}
	hashText := h.Sum(nil)
	return rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, hashText)
}

// RSA签名验证
func VerifyRSA(plainText, sig []byte, pubKeyFileName string) error  {
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

	pubKey := pub.(*rsa.PublicKey)

	h := sha512.New()
	_, err = h.Write(plainText)
	if err != nil {
		fmt.Println("h.Write(plainText) err=", err)
		return err
	}
	hashText := h.Sum(nil)

	return rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, hashText, sig)
}
