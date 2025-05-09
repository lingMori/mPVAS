package mpvasbase_test

// Package mpvasbase_test は mpvasbase をテストするパッケージ
// go test -json -v ./... 2>&1 | gotestfmt

import (
	"crypto/rand"
	"math/big"
	"strconv"
	"testing"

	mpvasbase "mPVAS/internal/crypto"

	bn256 "github.com/ethereum/go-ethereum/crypto/bn256/cloudflare"
	shamir "go.bryk.io/pkg/crypto/shamir"
)

func shamir_secrect_test(t *testing.T, secret string, n, k int) {

	// 秘密を分割
	shares, err := shamir.Split([]byte(secret), n, k)
	if err != nil {
		t.Error(err)
	}

	t.Logf("秘密を分割しました")
	for i, share := range shares {
		t.Logf("シェア%d: %d bytes", i+1, len(share))
	}

	// 秘密を復元
	recovered_secret, err := shamir.Combine(shares[:k])
	if err != nil {
		t.Error(err)
	}

	// 秘密が復元されたことを確認
	if string(recovered_secret) != secret {
		t.Error("秘密が復元されませんでした")
	} else {
		t.Log("秘密が復元されました")
	}
}

func InitialSignatureTest(t *testing.T, round int) {

	pp, users, err := mpvasbase.SetUp(10, 6)

	if err != nil {
		t.Errorf("err: %v", err)
	}

	t.Logf("初めのシグネチャを作成します　n: %d, k: %d", pp.N, pp.K)
	tRoundInitialSignature := make([]*bn256.G1, pp.N)
	// user signature collect
	for index, user := range users {
		t.Logf("user signature collect: %d", user.ID)
		// 数値と文字をreplace  (int ==> string)
		roundString := big.NewInt(int64(round)).Text(10)
		tRoundInitialSignature[user.ID], err = user.InitialSignature(roundString, big.NewInt(int64(index+2000)), pp)
	}

	t.Logf("初めのシグネチャを作成しました")

	// print tRoundInitialSignature
	for i, signature := range tRoundInitialSignature {
		t.Logf("tRoundInitialSignature[%d]: %.20s", i, signature.String())
	}

}

func MpvasBaseProtocolTest(t *testing.T, round int, n, k int) {

	pp, users, err := mpvasbase.SetUp(n, k)
	if err != nil {
		t.Errorf("err: %v", err)
	}
	t.Logf("mpvas base protocolを実行します　n: %d, k: %d", pp.N, pp.K)

	// aggregatorを生成し
	aggregator := mpvasbase.InitialAggregator(pp)

	roundMessage := "round-" + strconv.Itoa(round)
	userSecretInput := make([]*big.Int, pp.N)
	// set a sumX to check the aggregate value
	sumX := big.NewInt(0)

	for i := 0; i < pp.N; i++ {
		secretValue, _ := rand.Int(rand.Reader, pp.P)
		userSecretInput[i] = secretValue
		sumX.Add(sumX, secretValue)
		sumX.Mod(sumX, pp.P)
	}

	t.Logf("sumX: %s", sumX.String())

	// Signature Phase
	// 1. 署名者は、initial signature を生成し
	sigma1s := make([]*bn256.G1, pp.N)
	for i := 0; i < pp.N; i++ {
		sigma1s[i], err = users[i].InitialSignature(roundMessage, userSecretInput[i], pp)
		if err != nil {
			t.Errorf("err: %v", err)
		}
	}

	// 2. 署名者は、初期署名を集める
	sigma2s := make(map[int][]*bn256.G1, pp.N)
	for i := 0; i < pp.N; i++ {
		signSet := aggregator.SigningSet[i]
		sigma2s[i] = make([]*bn256.G1, len(signSet))

		for j := 0; j < len(signSet); j++ {
			sigma2s[i][j], err = users[signSet[j]].CooperativeSignature(roundMessage, sigma1s[i], pp, i)
			if err != nil {
				t.Errorf("err: %v", err)
			}
		}
	}

	// 3. 署名者は、署名を集める
}

func TestMpvasBaseProtocol(t *testing.T) {
	MpvasBaseProtocolTest(t, 1, 10, 6)
}
