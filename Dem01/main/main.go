package main

import "fmt"

// 测试文件
func main01() {
	encrypt := aesEncrypt([]byte("bitcoinandblockchain"), []byte("blockchablockcha"))
	plainText := aesDecrypt(encrypt, []byte("blockchablockcha"))
	fmt.Printf("encrypt=%s", plainText)
}

func main02() {
	err := GenerateRsaKey(1024)
	if err != nil {
		fmt.Println("err=", err)
	}
}

func main03() {
	cipherBytes, err := RSAEncrypt([]byte("maskcoinandbitcoin"), "public.pem")
	if err != nil {
		panic(err)
	}
	plainBytes, err := RSADecrypt(cipherBytes, "private.pem")
	if err != nil {
		panic(err)
	}
	fmt.Println("plainBytes =", string(plainBytes))
}

func main04()  {
	mac, err := GenerateHmac([]byte("bitmask"), []byte("hanxing614"))
	if err != nil {
		panic(err)
	}
	r, err := VerifyHmac([]byte("bitmask"), mac, []byte("hanxing614"))
	if err != nil {
		panic(err)
	}
	fmt.Println("mac=", r)
}

func main05()  {
	sig, err := SignatureRSA([]byte("xuaixin"), "private.pem")
	if err != nil {
		panic(err)
	}
	err = VerifyRSA([]byte("xuaixin"), sig, "public.pem")
	if err == nil {
		fmt.Println("RSA签名验证正确")
	} else {
		fmt.Println("RSA签名验证错误")
	}
}

func main06() {
	err := GenerateEccKey()
	if err != nil {
		panic(err)
	}
}

func main()  {
	rBytes, sBytes, err := EccSignature([]byte("blabblabla"), "eccPrivate.pem")
	if err != nil {
		panic(err)
	}
	err = ECCVerify([]byte("blabblabla"), rBytes, sBytes, "eccPublic.pem")
	if err != nil {
		panic(err)
	} else {
		fmt.Println("Ecc认证成功")
	}
}
