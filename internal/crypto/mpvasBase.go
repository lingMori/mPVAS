package mpvasbase

import (
	"crypto/rand"
	"fmt"
	"math/big"

	shamir "go.bryk.io/pkg/crypto/shamir"
	zap "go.uber.org/zap"
	"golang.org/x/crypto/bn256"
)

var logger *zap.Logger

func init() {
	logger, _ = zap.NewProduction()
}

// The public parameters are the parameters that are known by all the users.

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
	sumOfSki := new(big.Int).SetInt64(0)
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
		sumOfSki = new(big.Int).Add(sumOfSki, ski)
		sumOfSki = new(big.Int).Mod(sumOfSki, publicParams.P)
	}

	for i := range publicParams.N {

		sumKeys := new(big.Int).SetInt64(0)

		for j := 1; j <= publicParams.K; j++ {
			ek, err := rand.Int(rand.Reader, publicParams.P)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to generate ek: %v", err)
			}
			userKeys[i].EncKeys[j] = ek
			// logger.Info("the user's key is", zap.Int("user", i), zap.Int("key", j), zap.String("value", ek.String()))
			sumKeys = new(big.Int).Add(sumKeys, ek)
			sumKeys = new(big.Int).Mod(sumKeys, publicParams.P)
		}
		// logger.Info("the user's key is", zap.Int("user", i), zap.String("value", sumKeys.String()))
		lastKey := new(big.Int).Neg(sumKeys)
		lastKey = new(big.Int).Mod(lastKey, publicParams.P)
		userKeys[i].EncKeys[publicParams.K+1] = lastKey

		checkSumOfEnkeys(publicParams, userKeys[i])
	}

	// set vk
	g2s := new(bn256.G2).ScalarBaseMult(s)
	publicParams.VK1 = new(bn256.G2).ScalarMult(g2s, sumOfSki)
	publicParams.VK2 = g2s

	return publicParams, userKeys, nil

}

func (user *UserKey) Sign(round string, x *big.Int, publicParams *PublicParameters) (*bn256.G1, error) {
	// logger.Info("the user's key is", zap.Int("user", user.ID), zap.String("value", user.SK.String()))
	// logger.Info("the user's key is", zap.Int("user", user.ID), zap.String("value", user.SSShare.String()))
	// logger.Info("the user's key is", zap
	return nil, nil
}

func (user *UserKey) Verify(round string, x *big.Int, publicParams *PublicParameters) error {
	return nil
}

func checkSumOfEnkeys(publicParams *PublicParameters, userKeys *UserKey) error {
	// sum all key to check if the sum is 0
	sum := new(big.Int).SetInt64(0)
	for j := 1; j <= publicParams.K+1; j++ {
		sum = new(big.Int).Add(sum, userKeys.EncKeys[j])
		sum = new(big.Int).Mod(sum, publicParams.P)
	}
	if sum.Cmp(big.NewInt(0)) != 0 {
		return fmt.Errorf("the sum of keys is not 0")
	}

	return nil
}
