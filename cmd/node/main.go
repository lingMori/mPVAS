package main

import (
	"fmt"
	mpvasbase "mPVAS/internal/crypto"
)

func main() {

	publicParams, userKeys, err := mpvasbase.SetUp(10, 6)

	if err != nil {
		fmt.Println(err)
		return
	}

	// log structure data of pp and userkeys

	fmt.Println(publicParams)
	fmt.Println(userKeys)

}
