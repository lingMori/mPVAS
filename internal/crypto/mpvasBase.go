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
	N   int       // Total number of users
	K   int       // Maximum number of malicious users
	VK1 *bn256.G2 // Verification key 1: (g2^s)^{\sum ski}
	VK2 *bn256.G2 // Verification key 2: g2^s
}

type UserKey struct {
	ID                   int
	SK                   *big.Int // signature key
	SSShare              *big.Int
	EncKeys              map[int]*big.Int
	LagrangeCoefficients map[int]*big.Int
}

func SetUp(n, k int) (*PublicParameters, []*UserKey, error) {
	if k >= n-1 {
		return nil, nil, fmt.Errorf("k must less than n-1")
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
		return nil, nil, nil
	}

	// split secret into n pieces
	shares, err := shamir.Split(s.Bytes(), publicParams.N, publicParams.K+1)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split secret: %v", err)
	}

	// generate userkey
	userKeys := make([]*UserKey, publicParams.N)
	for i := 0; i < publicParams.N; i++ {
		ski, err := rand.Int(rand.Reader, publicParams.P)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ski: %v", err)
		}

		userKeys[i] = &UserKey{
			ID:                   i,
			SK:                   ski,
			SSShare:              new(big.Int).SetBytes(shares[i]),
			EncKeys:              make(map[int]*big.Int),
			LagrangeCoefficients: make(map[int]*big.Int),
		}
	}

	for i := 0; i < publicParams.N; i++ {

		sumKeys := new(big.Int).SetInt64(0)

		for j := 0; j < publicParams.K+1; j++ {
			ek, err := rand.Int(rand.Reader, publicParams.P)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate ek: %v", err)
			}
			userKeys[i].EncKeys[j] = ek
			sumKeys = new(big.Int).Add(sumKeys, ek)
			sumKeys = new(big.Int).Mod(sumKeys, publicParams.P)
		}

		lastKey := new(big.Int).Neg(sumKeys)
		lastKey = new(big.Int).Mod(lastKey, publicParams.P)
		userKeys[i].EncKeys[publicParams.K+1] = lastKey
	}

	// precompute lagrange coefficients

	return publicParams, userKeys, nil

}
