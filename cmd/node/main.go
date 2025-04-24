package main

import (
	"fmt"
	mpvasbase "mPVAS/internal/crypto"
	"math/big"
)

func main() {

	publicParams, userKeys, err := mpvasbase.SetUp(10, 6)

	if err != nil {
		fmt.Println(err)
		return
	}

	// log structure data of pp and userkeys

	for index, userkey := range userKeys {
		// transfer int index to string index
		if index > 5 {
			return
		}
		indexString := fmt.Sprintf("%d", index)
		sigma_1, err := userkey.Sign_1(indexString, new(big.Int).SetInt64(1293671238712312387), publicParams)
		if err != nil {
			fmt.Println(fmt.Errorf("error in signing: %s", err))
			return
		}
		sigma_2, err := userkey.Sign_2(indexString, sigma_1, publicParams)
		if err != nil {
			fmt.Println(fmt.Errorf("error in signing: %s", err))
			return
		}

		fmt.Print(sigma_2)
	}

}
