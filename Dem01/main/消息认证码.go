package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
)

// 生成消息认证码
func GenerateHmac(plainText, key []byte) ([]byte, error) {
	h := hmac.New(sha1.New, key)
	_, err := h.Write(plainText)
	if err != nil {
		fmt.Println("h.Write(plainText) err=", err)
		return nil, err
	}
	retBytes := h.Sum(nil)
	return retBytes, err
}

// 验证消息认证码
func VerifyHmac(plainText, hashText, key []byte) (bool,error) {
	 mac, err := GenerateHmac(plainText, key)
	if err != nil {
		return false, err
	}
	return hmac.Equal(mac, hashText), nil
}