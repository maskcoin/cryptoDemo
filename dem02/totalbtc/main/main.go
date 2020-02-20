package main

import "fmt"

func main()  {
	//1.每21万个块减半
	//2.最初奖励50个btc
	//3.用一个循环来判断
	total := 0.0
	blockInterval := 21.0 //单位是万
	currentReward := 50.0
	for currentReward > 0{
		amount1 := blockInterval * currentReward

		currentReward *= 0.5
		total += amount1
	}
	fmt.Println("比特币总量：", total)
}
