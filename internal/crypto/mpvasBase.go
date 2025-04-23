package mpvasbase

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	shamir "go.bryk.io/pkg/crypto/shamir"
	zap "go.uber.org/zap"
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

type Aggeregators struct {
	PublicParams *PublicParameters
	SigningSet   map[int][]int // SigningSet[i] means a set of users ID who sign for user[i]
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

func (user *UserKey) Sign_1(round string, x *big.Int, publicParams *PublicParameters) (*bn256.G1, error) {
	// logger.Info("the user's key is", zap.Int("user", user.ID), zap.String("value", user.SK.String()))
	// logger.Info("the user's key is", zap.Int("user", user.ID), zap.String("value", user.SSShare.String()))
	// logger.Info("the user's key is", zap

	// fiset step: create initial signature
	// H(t)^sk_i
	Ht := Hash_org([]byte(round))
	Ht_ski := new(bn256.G1).ScalarMult(Ht, user.SK)

	g1_x := new(bn256.G1).ScalarBaseMult(x)
	sign_1 := new(bn256.G1).Add(Ht_ski, g1_x)

	return sign_1, nil
}

func (user *UserKey) Sign_2(round string, sign_1 *bn256.G1, publicParams *PublicParameters) (*bn256.G1, error) {
	// user i generate sign_2_j under user j's key and secret

	// H1(t)^ekj,i
	H1t := Hash_1([]byte(round))
	H1t_ekji := new(bn256.G1).ScalarMult(H1t, user.EncKeys[user.ID])

	//sign_1^[s]j
	sign_1_sj := new(bn256.G1).ScalarMult(sign_1, user.SSShare)

	sign_2 := new(bn256.G1).Add(H1t_ekji, sign_1_sj)
	return sign_2, nil
}

func (user *UserKey) Sign_4(round string, sign_3 *bn256.G1, x *big.Int, publicParams *PublicParameters) (*bn256.G1, error) {
	// user i generate sign_4 under user i's key and secret

	// H1(t)^ekj,i
	H1t := Hash_1([]byte(round))
	H1t_ekii := new(bn256.G1).ScalarMult(H1t, user.EncKeys[user.ID])

	Ht := Hash_org([]byte(round))
	Ht_ski := new(bn256.G1).ScalarMult(Ht, user.SK)

	g1_x := new(bn256.G1).ScalarBaseMult(x)

	temp := new(bn256.G1).Add(Ht_ski, g1_x)
	temp_ss := new(bn256.G1).ScalarMult(temp, user.SSShare)

	sign_4Result := new(bn256.G1).Add(H1t_ekii, temp_ss)
	sign_4Result = new(bn256.G1).Add(sign_3, sign_4Result)

	return sign_4Result, nil
}

// orignal hash function H: {0, 1}* -> G1
func Hash_org(data []byte) *bn256.G1 {
	hash := sha256.Sum256(data)
	// conver hash data to big.int
	hashint := new(big.Int).SetBytes(hash[:])
	hashint = new(big.Int).Mod(hashint, bn256.Order)

	return new(bn256.G1).ScalarBaseMult(hashint)
}

// hash function H1: {0, 1}* -> G2
func Hash_1(data []byte) *bn256.G1 {
	hash := sha256.Sum256(append([]byte("H1"), data...))
	// conver hash data to big.int
	hashint := new(big.Int).SetBytes(hash[:])
	hashint = new(big.Int).Mod(hashint, bn256.Order)

	return new(bn256.G1).ScalarBaseMult(hashint)
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
