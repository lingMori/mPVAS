package mpvasbase

import (
	"crypto/rand"
	"fmt"
	"math/big"

	shamir "go.bryk.io/pkg/crypto/shamir"
	"golang.org/x/crypto/bn256"
)

// public parameters pp = (H, H1, G1, G2, GT , g1, g2, e, p, n, k),
type PublicParameters struct {
	// H1 hash function
	// H  hash function
	G1  *bn256.G1
	G2  *bn256.G2
	GT  *bn256.GT
	P   *big.Int
	N   int // user num
	K   int // malicous num
	VK1 *bn256.G2
	VK2 *bn256.G2
}

func SetUp(n, k int) (*PublicParameters, error) {
	if k >= n-1 {
		return nil, fmt.Errorf("k must less than n-1")
	}

	publicParams := &PublicParameters{
		G1: new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
		G2: new(bn256.G2).ScalarBaseMult(big.NewInt(1)),
		P:  bn256.Order,
		N:  n,
		K:  k,
	}

	// generate shamir secret share: s
	s, err := rand.Int(rand.Reader, publicParams.P)
	if err != nil {
		return nil, nil
	}

	// split secret into n pieces
	shares, err := shamir.Split(s.Bytes(), publicParams.N, publicParams.K)

	// print shares for test
	for i := 0; i < publicParams.N; i++ {
		fmt.Println("share", i, shares[i])
	}

	return publicParams, nil
}
