package mpvasbase_test

import (
	"testing"

	shamir "go.bryk.io/pkg/crypto/shamir"
)

func shamir_secrect_test(t *testing.T, secret string, n, k int) {

	// 秘密を分割
	shares, err := shamir.Split([]byte(secret), n, k)
	if err != nil {
		t.Error(err)
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

func TestMpvasbase(t *testing.T) {
	secrect := "123456"

	shamir_secrect_test(t, secrect, 10, 5)
	shamir_secrect_test(t, secrect, 10, 6)
	shamir_secrect_test(t, secrect, 10, 7)
	shamir_secrect_test(t, secrect, 10, 8)
}
