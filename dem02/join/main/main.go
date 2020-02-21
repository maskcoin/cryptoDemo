package main

import (
	"bytes"
	"fmt"
)

func main()  {
	//str1 := []string{"hello", "world", "!"}
	//str := strings.Join(str1, "")
	//fmt.Printf("res: %s", str)

	bytes := bytes.Join([][]byte{[]byte("hello"), []byte("world"), []byte("!")}, nil)
	fmt.Printf("bytes = %s\n", bytes)
}
