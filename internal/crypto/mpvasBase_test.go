package mpvasbase

import (
	// For comparing marshalled points
	crypto_rand "crypto/rand" // Alias to avoid conflict with kyber's random
	"math/big"
	"testing"

	// bn256_kyber "github.com/drand/kyber/pairing/bn256" // Removed
	// "github.com/drand/kyber/util/random" // Removed
	// "github.com/drand/kyber" // Removed
	bn256 "github.com/cloudflare/bn256"
	"github.com/stretchr/testify/require"
)

func TestMPVASProtocol_FullFlow(t *testing.T) {
	// Protocol Parameters
	n_users := 1000
	k_malicious_max := 100

	if n_users < k_malicious_max+2 {
		t.Fatalf("Test setup invalid: N must be >= K+2. N=%d, K=%d", n_users, k_malicious_max)
	}

	// 1. Setup Phase (Dealer)
	dealer, pp := NewDealer(n_users, k_malicious_max)

	// Users generate their private signature keys (ski)
	allUserPrivateSigKeys := make([]*big.Int, n_users)
	for i := 0; i < n_users; i++ {
		ski, err := crypto_rand.Int(crypto_rand.Reader, Order)
		require.NoError(t, err)
		allUserPrivateSigKeys[i] = ski
	}

	users, verificationKey, err := dealer.Setup(allUserPrivateSigKeys)
	require.NoError(t, err, "Dealer setup failed")
	require.Len(t, users, n_users, "Incorrect number of users initialized")
	require.NotNil(t, verificationKey, "Verification key is nil")

	// Verify sum of all encryption keys is zero (for debugging dealer setup)
	sumAllEkCheck := big.NewInt(0)
	for _, u := range users {
		require.Len(t, u.EncryptionKeys, k_malicious_max+1, "User has incorrect number of encryption keys")
		for _, ek := range u.EncryptionKeys {
			sumAllEkCheck.Add(sumAllEkCheck, ek)
			sumAllEkCheck.Mod(sumAllEkCheck, Order)
		}
	}
	require.True(t, sumAllEkCheck.Cmp(big.NewInt(0)) == 0, "Sum of all encryption keys is not zero after setup")

	// 2. Signing Phase
	aggregator := NewAggregator(pp, users)
	round_t_data := []byte("round_data_for_t_123")

	// Each user has a private input xi,t
	userPrivateInputs_xi_t := make([]*big.Int, n_users)
	sum_total_xi_t := big.NewInt(0)
	for i := 0; i < n_users; i++ {
		inputVal := big.NewInt(int64(10 * (i + 1))) // Example input
		userPrivateInputs_xi_t[i] = inputVal
		users[i].PrivateInput = new(big.Int).Set(inputVal) // Set it in the user struct as well
		sum_total_xi_t.Add(sum_total_xi_t, inputVal)
		sum_total_xi_t.Mod(sum_total_xi_t, Order)
	}

	// Storage for intermediate signatures
	initialSignatures_sigma1 := make(map[int]*bn256.G1) // originator_userID -> sigma1
	finalUserSignatures_sigma_i_t := make([]*bn256.G1, 0, n_users)

	// --- For each user i (originator) ---
	for i := 0; i < n_users; i++ {
		originatorUser := users[i]
		t.Logf("Processing for originator user %d", originatorUser.ID)

		// a) Originator user i creates initial signature σ1_i,t
		sigma1_i_t := originatorUser.CreateInitialSignature(round_t_data, originatorUser.PrivateInput)
		initialSignatures_sigma1[originatorUser.ID] = sigma1_i_t
		t.Logf("  User %d created σ1_%d,t", originatorUser.ID, originatorUser.ID)

		// b) Aggregator prepares for user i's signature (selects Ui, assigns originator's EKs)
		helperUserIDs_Ui, participantXsForS, err_prep := aggregator.PrepareForUserISigning(originatorUser.ID)
		require.NoError(t, err_prep, "Aggregator failed to prepare for user %d signing", originatorUser.ID)
		require.Len(t, helperUserIDs_Ui, k_malicious_max, "Incorrect number of helpers in Ui")
		require.Len(t, participantXsForS, k_malicious_max+1, "Incorrect number of participant X's for S reconstruction")

		xMap := make(map[string]bool)
		for _, xVal := range participantXsForS {
			require.False(t, xMap[xVal.String()], "Participant X values for S reconstruction are not distinct: %v", participantXsForS)
			xMap[xVal.String()] = true
		}

		// c) Each helper user j ∈ Ui creates partial signature σ2,j_i,t
		partialSignatures_sigma2_for_i := make([]*bn256.G1, k_malicious_max)
		for idx, helperID := range helperUserIDs_Ui {
			helperUser := users[helperID-1]

			assigned_ek_for_helper, err_get_ek := aggregator.GetEncryptionKeyForHelper(originatorUser.ID, helperID)
			require.NoError(t, err_get_ek, "Failed to get EK for helper %d from aggregator", helperID)

			t.Logf("    Helper user %d creating σ2 for originator %d using its [s*] and originator's EK", helperUser.ID, originatorUser.ID)
			sigma2_j_i_t, err_partial := helperUser.CreatePartialSignature(
				round_t_data,
				sigma1_i_t,
				assigned_ek_for_helper,
				participantXsForS,
			)
			require.NoError(t, err_partial, "Helper user %d failed to create partial signature for user %d", helperUser.ID, originatorUser.ID)
			partialSignatures_sigma2_for_i[idx] = sigma2_j_i_t
		}

		// d) Aggregator combines partials to get σ3_i,t
		sigma3_i_t := aggregator.CombinePartialSignatures(partialSignatures_sigma2_for_i)
		t.Logf("  Aggregator computed σ3_%d,t for user %d", originatorUser.ID, originatorUser.ID)

		// e) Originator user i computes final user signature σ_i,t
		ek_self_for_originator, err_get_self_ek := aggregator.GetSelfEncryptionKey(originatorUser.ID)
		require.NoError(t, err_get_self_ek, "Failed to get self-EK for originator %d from aggregator", originatorUser.ID)

		sigma_i_t, err_final_sig := originatorUser.ComputeFinalUserSignature(
			round_t_data,
			sigma3_i_t,
			sigma1_i_t,
			ek_self_for_originator,
			participantXsForS,
		)
		require.NoError(t, err_final_sig, "Originator user %d failed to compute final signature", originatorUser.ID)
		finalUserSignatures_sigma_i_t = append(finalUserSignatures_sigma_i_t, sigma_i_t)
		t.Logf("  User %d computed final σ_%d,t", originatorUser.ID, originatorUser.ID)

		// Sanity check: reconstruct s
		s_reconstructed_check := big.NewInt(0)
		s_contrib_originator, err_s_orig := originatorUser.computeShamirSContribution(participantXsForS)
		require.NoError(t, err_s_orig)
		s_reconstructed_check.Add(s_reconstructed_check, s_contrib_originator)

		for _, helperID := range helperUserIDs_Ui {
			helperUser := users[helperID-1]
			s_contrib_helper, err_s_helper := helperUser.computeShamirSContribution(participantXsForS)
			require.NoError(t, err_s_helper)
			s_reconstructed_check.Add(s_reconstructed_check, s_contrib_helper)
		}
		s_reconstructed_check.Mod(s_reconstructed_check, Order)
		require.True(t, dealer.s.Cmp(s_reconstructed_check) == 0, "Reconstructed s does not match original s for user %d's signature process. Original: %s, Reconstructed: %s", originatorUser.ID, dealer.s.String(), s_reconstructed_check.String())
		t.Logf("  Sanity check: s successfully reconstructed for user %d's signature (s_orig=%s..., s_recon=%s...)", originatorUser.ID, dealer.s.String()[:10], s_reconstructed_check.String()[:10])

		// Sanity check: sum of EKs used for this sigma_i_t
		sum_eki_l_for_user_i := big.NewInt(0)
		for _, ek := range originatorUser.EncryptionKeys {
			sum_eki_l_for_user_i.Add(sum_eki_l_for_user_i, ek)
		}
		sum_eki_l_for_user_i.Mod(sum_eki_l_for_user_i, Order)

		sum_eks_used_in_sigma_i_t := big.NewInt(0)
		sum_eks_used_in_sigma_i_t.Add(sum_eks_used_in_sigma_i_t, ek_self_for_originator)
		for _, helperID := range helperUserIDs_Ui {
			assigned_ek, _ := aggregator.GetEncryptionKeyForHelper(originatorUser.ID, helperID)
			sum_eks_used_in_sigma_i_t.Add(sum_eks_used_in_sigma_i_t, assigned_ek)
		}
		sum_eks_used_in_sigma_i_t.Mod(sum_eks_used_in_sigma_i_t, Order)
		require.True(t, sum_eki_l_for_user_i.Cmp(sum_eks_used_in_sigma_i_t) == 0, "Sum of EKs used for σ_%d,t (%s) != sum of user %d's EKs (%s)",
			originatorUser.ID, sum_eks_used_in_sigma_i_t.String()[:10], originatorUser.ID, sum_eki_l_for_user_i.String()[:10])
		t.Logf("  Sanity check: Sum of EKs for σ_%d,t matches user %d's total EKs.", originatorUser.ID, originatorUser.ID)
	}

	// 3. Signature Aggregation
	aggregate_sigma_t := aggregator.AggregateFinalUserSignatures(finalUserSignatures_sigma_i_t)
	t.Logf("Aggregator computed final aggregate signature σ_t")

	// 4. Verification
	isValid := VerifySignature(pp, verificationKey, round_t_data, sum_total_xi_t, aggregate_sigma_t)
	require.True(t, isValid, "Aggregate signature verification FAILED")
	t.Logf("SUCCESS: Aggregate signature verified successfully!")

	// Test with tampered sum
	tampered_sum_xi_t := new(big.Int).Add(sum_total_xi_t, big.NewInt(1))
	tampered_sum_xi_t.Mod(tampered_sum_xi_t, Order)
	isTamperedValid := VerifySignature(pp, verificationKey, round_t_data, tampered_sum_xi_t, aggregate_sigma_t)
	require.False(t, isTamperedValid, "Verification unexpectedly PASSED with tampered sum_xi_t")
	t.Logf("SUCCESS: Verification correctly FAILED with tampered sum_xi_t.")

	// Test with tampered aggregate signature
	tampered_sigma_t := new(bn256.G1).Add(aggregate_sigma_t, pp.g1)
	isTamperedSigValid := VerifySignature(pp, verificationKey, round_t_data, sum_total_xi_t, tampered_sigma_t)
	require.False(t, isTamperedSigValid, "Verification unexpectedly PASSED with tampered aggregate_sigma_t")
	t.Logf("SUCCESS: Verification correctly FAILED with tampered aggregate_sigma_t.")
}

// func TestLagrangeCoefficient(t *testing.T) {
// 	p_order := Order // Use the global Order

// 	x_coords_1 := []*big.Int{big.NewInt(1), big.NewInt(2)}
// 	evalAtZero := big.NewInt(0)

// 	l1_0, err := computeLagrangeCoefficient(evalAtZero, big.NewInt(1), x_coords_1, p_order)
// 	require.NoError(t, err)
// 	require.Equal(t, big.NewInt(2).String(), l1_0.String(), "L_1(0) incorrect")

// 	l2_0, err := computeLagrangeCoefficient(evalAtZero, big.NewInt(2), x_coords_1, p_order)
// 	require.NoError(t, err)
// 	expected_l2_0 := new(big.Int).Sub(p_order, big.NewInt(1))
// 	require.Equal(t, expected_l2_0.String(), l2_0.String(), "L_2(0) incorrect")

// 	x_coords_2 := []*big.Int{big.NewInt(2), big.NewInt(4), big.NewInt(5)}
// 	l2_0_c2, err := computeLagrangeCoefficient(evalAtZero, big.NewInt(2), x_coords_2, p_order)
// 	require.NoError(t, err)

// 	term1_num := new(big.Int).Sub(evalAtZero, big.NewInt(4))
// 	term1_den := new(big.Int).Sub(big.NewInt(2), big.NewInt(4))
// 	term1 := new(big.Int).Mul(term1_num, new(big.Int).ModInverse(term1_den, p_order))
// 	term1.Mod(term1, p_order)

// 	term2_num := new(big.Int).Sub(evalAtZero, big.NewInt(5))
// 	term2_den := new(big.Int).Sub(big.NewInt(2), big.NewInt(5))
// 	term2 := new(big.Int).Mul(term2_num, new(big.Int).ModInverse(term2_den, p_order))
// 	term2.Mod(term2, p_order)

// 	expected_l2_0_c2 := new(big.Int).Mul(term1, term2)
// 	expected_l2_0_c2.Mod(expected_l2_0_c2, p_order)
// 	require.Equal(t, expected_l2_0_c2.String(), l2_0_c2.String(), "L_2(0) for case 2 incorrect")

// 	x_coords_3 := []*big.Int{big.NewInt(1)}
// 	l1_0_c3, err := computeLagrangeCoefficient(evalAtZero, big.NewInt(1), x_coords_3, p_order)
// 	require.NoError(t, err)
// 	require.Equal(t, big.NewInt(1).String(), l1_0_c3.String(), "L_1(0) for K+1=1 incorrect")
// }

// func TestShamirReconstruction(t *testing.T) {
// 	n_users := 5
// 	k_plus_1_threshold := 3
// 	p_order := Order

// 	secret_s, err := crypto_rand.Int(crypto_rand.Reader, p_order)
// 	require.NoError(t, err)

// 	shares, err_shares := generateShamirSharesCorrected(secret_s, n_users, k_plus_1_threshold, p_order)
// 	require.NoError(t, err_shares, "Shamir share generation failed")
// 	require.Len(t, shares, n_users)

// 	recon_shares_coords := make([]*big.Int, k_plus_1_threshold)
// 	recon_share_values_y := make([]*big.Int, k_plus_1_threshold)
// 	for i := 0; i < k_plus_1_threshold; i++ {
// 		recon_shares_coords[i] = shares[i].X
// 		recon_share_values_y[i] = shares[i].Y
// 	}

// 	reconstructed_s_bigint := big.NewInt(0)
// 	evalAtZero := big.NewInt(0)

// 	for i := 0; i < k_plus_1_threshold; i++ {
// 		lagrange_coeff_Li_0, err_lagrange := computeLagrangeCoefficient(evalAtZero, recon_shares_coords[i], recon_shares_coords, p_order)
// 		require.NoError(t, err_lagrange, "Lagrange computation failed during reconstruction test")

// 		term := new(big.Int).Mul(recon_share_values_y[i], lagrange_coeff_Li_0)
// 		term.Mod(term, p_order)

// 		reconstructed_s_bigint.Add(reconstructed_s_bigint, term)
// 		reconstructed_s_bigint.Mod(reconstructed_s_bigint, p_order)
// 	}

// 	require.True(t, secret_s.Cmp(reconstructed_s_bigint) == 0, "Reconstructed secret s does not match original. Original: %s, Reconstructed: %s", secret_s.String(), reconstructed_s_bigint.String())
// 	t.Logf("Shamir secret successfully reconstructed: s_orig=%s..., s_recon=%s...", secret_s.String()[:10], reconstructed_s_bigint.String()[:10])
// }

// // valStr helper can remain the same if used.

// func TestPointSerialization(t *testing.T) {
// 	// Test G1 point serialization
// 	s1_rand, _ := crypto_rand.Int(crypto_rand.Reader, Order)
// 	p1 := new(bn256.G1).ScalarBaseMult(s1_rand)
// 	p1Bytes := p1.Marshal() // cloudflare/bn256 uses Marshal() which returns []byte

// 	p2 := new(bn256.G1)
// 	_, err_unmarshal := p2.Unmarshal(p1Bytes) // Unmarshal returns the unconsumed tail, error
// 	require.NoError(t, err_unmarshal)
// 	require.True(t, bytes.Equal(p1.Marshal(), p2.Marshal()), "Point G1 unmarshal failed")

// 	// Test *big.Int (scalar) serialization (using Bytes() and SetBytes())
// 	scalar1, _ := crypto_rand.Int(crypto_rand.Reader, Order)
// 	s1Bytes := scalar1.Bytes()

// 	scalar2 := new(big.Int)
// 	scalar2.SetBytes(s1Bytes)
// 	require.True(t, scalar1.Cmp(scalar2) == 0, "Scalar (*big.Int) unmarshal failed")
// }

// func TestLagrange_K0_Threshold1(t *testing.T) {
// 	p_order := Order
// 	evalAtZero := big.NewInt(0)

// 	participant_x := big.NewInt(5)
// 	all_xs := []*big.Int{participant_x}

// 	l_coeff, err := computeLagrangeCoefficient(evalAtZero, participant_x, all_xs, p_order)
// 	require.NoError(t, err)
// 	require.Equal(t, "1", l_coeff.String(), "Lagrange coeff for single participant (threshold 1) should be 1")
// }

// func TestDistinctParticipantXsForS(t *testing.T) {
// 	n_users := 3
// 	k_malicious_max := 1

// 	_, pp := NewDealer(n_users, k_malicious_max)

// 	mockUsers := make([]*User, n_users)
// 	for i := 0; i < n_users; i++ {
// 		// Ensure EncryptionKeys is correctly typed and initialized
// 		encKeys := make([]*big.Int, k_malicious_max+1)
// 		for j := range encKeys {
// 			encKeys[j] = big.NewInt(0) // Dummy value
// 		}
// 		mockUsers[i] = &User{
// 			ID:             i + 1,
// 			pp:             pp,
// 			shamirShareX:   big.NewInt(int64(i + 1)),
// 			EncryptionKeys: encKeys,
// 		}
// 	}
// 	agg := NewAggregator(pp, mockUsers)

// 	for originatorID := 1; originatorID <= n_users; originatorID++ {
// 		_, participantXs, err := agg.PrepareForUserISigning(originatorID)
// 		require.NoError(t, err, "PrepareForUserISigning failed for user %d", originatorID)
// 		require.Len(t, participantXs, k_malicious_max+1, "Incorrect number of participants for S for user %d", originatorID)

// 		seen := make(map[string]bool)
// 		for _, x := range participantXs {
// 			require.False(t, seen[x.String()], "Duplicate X coordinate found: %s in %v for originator %d", x.String(), participantXs, originatorID)
// 			seen[x.String()] = true
// 		}
// 		t.Logf("For originator %d, participantXsForS: %v", originatorID, participantXs)
// 	}
// }
