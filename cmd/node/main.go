package main

import (
	"fmt"
	mpvasbase "mPVAS/internal/crypto"
)

func main() {

	publicParams, err := mpvasbase.SetUp(10, 6)

	if err != nil {
		fmt.Println(err)
		return
	}

	// print public params
	fmt.Println(publicParams)

}
