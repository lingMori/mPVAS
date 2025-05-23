package mpvas

import (
	"bytes" // For comparing GT points
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	bn256 "github.com/cloudflare/bn256"
	// "github.com/drand/kyber" // Removed
	// "github.com/drand/kyber/pairing/bn256" // Removed
	// "github.com/drand/kyber/util/random" // Removed
)

// Global curve parameters
var G1Gen = new(bn256.G1).ScalarBaseMult(big.NewInt(1)) // G1 generator
var G2Gen = new(bn256.G2).ScalarBaseMult(big.NewInt(1)) // G2 generator
var Order = bn256.Order                                 // Prime order p of the groups (a *big.Int)

// PublicParams stores the public parameters for mPVAS
type PublicParams struct {
	H  func(data []byte) *bn256.G1                // Hash to G1
	H1 func(data []byte) *bn256.G1                // Hash to G1 (distinct from H)
	g1 *bn256.G1                                  // Generator of G1
	g2 *bn256.G2                                  // Generator of G2
	e  func(p1 *bn256.G1, p2 *bn256.G2) *bn256.GT // Bilinear pairing e: G1xG2 -> GT
	P  *big.Int                                   // Order of the groups (same as Order)
	N  int                                        // Number of users
	K  int                                        // Max malicious users (threshold K+1 for Shamir)
}

// VerificationKey is the public key for verification
type VerificationKey struct {
	VK1 *bn256.G2 // g2^(s * sum(ski))
	VK2 *bn256.G2 // g2^s
}

// User holds data for a single user
type User struct {
	ID             int
	pp             *PublicParams
	shamirShareX   *big.Int   // x_i (user's ID, used in Shamir's)
	shamirShareY   *big.Int   // y_i = S(x_i), Shamir share y-coordinate
	EncryptionKeys []*big.Int // User i's batch of K+1 encryption keys {eki,j} (scalars)
	SignatureKey   *big.Int   // ski, user's private signature key (scalar)
	PrivateInput   *big.Int   // xi,t (user's input for a round t) (scalar)
}

// ShamirShare represents a point (x, P(x)) on the secret-sharing polynomial
type ShamirShare struct {
	X, Y *big.Int
}

// Dealer handles the setup phase of the protocol
type Dealer struct {
	pp *PublicParams
	s  *big.Int // Master secret s (scalar)
}

// Aggregator handles communication and aggregation steps during signing
type Aggregator struct {
	pp                          *PublicParams
	Users                       []*User // Pointers to all users (for lookups)
	userEncryptionKeyForHelpers map[int]map[int]*big.Int
	userSelfEncryptionKey       map[int]*big.Int
}

// --- Cryptographic Helper Functions ---

// simplifiedHashToG1 hashes data to a point in G1 using cloudflare/bn256.
// WARNING: This is a simplified version for demonstration and NOT cryptographically secure
// for production. A standard like RFC 9380 (Hash-to-Curve) should be used.
func simplifiedHashToG1(domainSeparator []byte, data []byte) *bn256.G1 {
	fullData := append(domainSeparator, data...)
	hashedBytes := sha256.Sum256(fullData)

	k := new(big.Int).SetBytes(hashedBytes[:])
	k.Mod(k, Order) // Reduce k modulo the group order

	point := new(bn256.G1).ScalarBaseMult(k) // k * G1Gen
	return point
}

// H is the first hash function H: {0,1}* -> G1
func H_func(data []byte) *bn256.G1 {
	return simplifiedHashToG1([]byte("mPVAS_H_"), data)
}

// H1 is the second hash function H1: {0,1}* -> G1
func H1_func(data []byte) *bn256.G1 {
	return simplifiedHashToG1([]byte("mPVAS_H1_"), data)
}

// generateShamirSharesCorrected creates (threshold)-out-of-(nUsers) Shamir shares for secret s.
// The secret s is the value of the polynomial P(x) at x=0.
// Shares are (user_id, P(user_id)), where user_id are 1, 2, ..., nUsers.
// threshold is K+1 from the paper.
func generateShamirSharesCorrected(s *big.Int, nUsers, threshold int, p *big.Int) ([]ShamirShare, error) {
	if threshold > nUsers || threshold < 1 {
		return nil, fmt.Errorf("invalid threshold T=%d for N=%d users", threshold, nUsers)
	}
	degree := threshold - 1

	coeffs := make([]*big.Int, degree+1)
	coeffs[0] = new(big.Int).Set(s) // c_0 = s

	for i := 1; i <= degree; i++ {
		coeff_i, err := rand.Int(rand.Reader, p)
		if err != nil {
			return nil, fmt.Errorf("failed to generate random coefficient: %v", err)
		}
		coeffs[i] = coeff_i
	}

	shares := make([]ShamirShare, nUsers)
	for i := 0; i < nUsers; i++ {
		userIDBigInt := big.NewInt(int64(i + 1))
		y_i := big.NewInt(0)
		x_power_j := big.NewInt(1)

		for j := 0; j <= degree; j++ {
			term := new(big.Int).Mul(coeffs[j], x_power_j)
			term.Mod(term, p)
			y_i.Add(y_i, term)
			y_i.Mod(y_i, p)

			if j < degree {
				x_power_j.Mul(x_power_j, userIDBigInt)
				x_power_j.Mod(x_power_j, p)
			}
		}
		shares[i] = ShamirShare{X: new(big.Int).Set(userIDBigInt), Y: new(big.Int).Set(y_i)}
	}
	return shares, nil
}

// computeLagrangeCoefficient computes L_j(evalAtX) for participant j (identified by participantX_j)
// among a set of participants whose x-coordinates are in allDistinctParticipantXs.
// L_j(evalAtX) = product_{m!=j} (evalAtX - X_m) / (X_j - X_m) mod p.
func computeLagrangeCoefficient(evalAtX *big.Int, participantX_j *big.Int, allDistinctParticipantXs []*big.Int, p *big.Int) (*big.Int, error) {
	if len(allDistinctParticipantXs) == 0 {
		return nil, fmt.Errorf("participant list cannot be empty")
	}

	numerator := big.NewInt(1)
	denominator := big.NewInt(1)
	foundParticipantJ := false

	for _, currentX_m := range allDistinctParticipantXs {
		if currentX_m.Cmp(participantX_j) == 0 {
			foundParticipantJ = true
			continue
		}
		numTerm := new(big.Int).Sub(evalAtX, currentX_m)
		numTerm.Mod(numTerm, p)
		numerator.Mul(numerator, numTerm)
		numerator.Mod(numerator, p)

		denTerm := new(big.Int).Sub(participantX_j, currentX_m)
		denTerm.Mod(denTerm, p)
		if denTerm.Cmp(big.NewInt(0)) == 0 {
			return nil, fmt.Errorf("denominator term is zero, participantX_j=%s, currentX_m=%s. IDs might not be distinct.", participantX_j.String(), currentX_m.String())
		}
		denominator.Mul(denominator, denTerm)
		denominator.Mod(denominator, p)
	}

	if !foundParticipantJ && len(allDistinctParticipantXs) > 0 {
		return nil, fmt.Errorf("participantX_j %s not found in allDistinctParticipantXs %v", participantX_j.String(), allDistinctParticipantXs)
	}
	if len(allDistinctParticipantXs) == 1 && !foundParticipantJ {
		return nil, fmt.Errorf("participantX_j %s not found in single-element list %v", participantX_j.String(), allDistinctParticipantXs)
	}
	if len(allDistinctParticipantXs) == 1 && foundParticipantJ {
		return big.NewInt(1), nil
	}

	invDenominator := new(big.Int).ModInverse(denominator, p)
	if invDenominator == nil {
		return nil, fmt.Errorf("modular inverse of denominator failed. Denom: %s", denominator.String())
	}

	result := new(big.Int).Mul(numerator, invDenominator)
	result.Mod(result, p)
	return result, nil
}

// --- Dealer Methods ---

// NewDealer creates a new Dealer instance.
func NewDealer(n_users, k_malicious_max int) (*Dealer, *PublicParams) {
	if k_malicious_max > n_users-2 {
		panic(fmt.Sprintf("k (max malicious users = %d) must be <= n-2 (n=%d)", k_malicious_max, n_users))
	}
	pp := &PublicParams{
		H:  H_func,
		H1: H1_func,
		g1: G1Gen,
		g2: G2Gen,
		e:  bn256.Pair,
		P:  Order,
		N:  n_users,
		K:  k_malicious_max,
	}
	s_secret, err := rand.Int(rand.Reader, Order)
	if err != nil {
		panic(fmt.Sprintf("failed to generate master secret s: %v", err))
	}
	return &Dealer{pp: pp, s: s_secret}, pp
}

// Setup initializes users and computes the public verification key.
func (d *Dealer) Setup(allUserPrivateSigKeys []*big.Int) ([]*User, *VerificationKey, error) {
	n := d.pp.N
	k_plus_1_threshold := d.pp.K + 1
	p_order := d.pp.P

	if len(allUserPrivateSigKeys) != n {
		return nil, nil, fmt.Errorf("number of signature keys (%d) must match N (%d)", len(allUserPrivateSigKeys), n)
	}

	shamirShares, err := generateShamirSharesCorrected(d.s, n, k_plus_1_threshold, p_order)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate Shamir shares: %v", err)
	}

	allUsersEncKeys := make([][]*big.Int, n)
	sumOfAll_eki_j := big.NewInt(0)

	for i := 0; i < n; i++ {
		allUsersEncKeys[i] = make([]*big.Int, k_plus_1_threshold)
		for j := 0; j < k_plus_1_threshold; j++ {
			if i == n-1 && j == d.pp.K {
				continue
			}
			key, err_key := rand.Int(rand.Reader, Order)
			if err_key != nil {
				return nil, nil, fmt.Errorf("failed to generate encryption key: %v", err_key)
			}
			allUsersEncKeys[i][j] = key
			sumOfAll_eki_j.Add(sumOfAll_eki_j, key)
			sumOfAll_eki_j.Mod(sumOfAll_eki_j, Order)
		}
	}

	ek_n_Kplus1 := new(big.Int).Neg(sumOfAll_eki_j)
	ek_n_Kplus1.Mod(ek_n_Kplus1, Order)
	allUsersEncKeys[n-1][d.pp.K] = ek_n_Kplus1

	users := make([]*User, n)
	for i := 0; i < n; i++ {
		users[i] = &User{
			ID:             i + 1,
			pp:             d.pp,
			shamirShareX:   new(big.Int).Set(shamirShares[i].X),
			shamirShareY:   new(big.Int).Set(shamirShares[i].Y),
			EncryptionKeys: allUsersEncKeys[i],
			SignatureKey:   allUserPrivateSigKeys[i],
		}
	}

	g2_s := new(bn256.G2).ScalarBaseMult(d.s) // vk2 = s * g2

	sum_ski := big.NewInt(0)
	for _, ski := range allUserPrivateSigKeys {
		sum_ski.Add(sum_ski, ski)
	}
	sum_ski.Mod(sum_ski, Order)

	s_mul_sum_ski := new(big.Int).Mul(d.s, sum_ski)
	s_mul_sum_ski.Mod(s_mul_sum_ski, Order)
	vk1 := new(bn256.G2).ScalarBaseMult(s_mul_sum_ski) // vk1 = (s * sum_ski) * g2

	verificationKey := &VerificationKey{
		VK1: vk1,
		VK2: g2_s,
	}

	return users, verificationKey, nil
}

// --- User Methods ---

// CreateInitialSignature computes σ1_i,t = ski * H(t) + xi,t * g1
func (u *User) CreateInitialSignature(t_data []byte, privateInput_xi_t *big.Int) *bn256.G1 {
	u.PrivateInput = privateInput_xi_t

	ht := u.pp.H(t_data)
	ht_pow_ski := new(bn256.G1).ScalarMult(ht, u.SignatureKey) // ski * H(t)

	g1_pow_xit := new(bn256.G1).ScalarBaseMult(privateInput_xi_t) // xi,t * g1

	sigma1_i_t := new(bn256.G1).Add(ht_pow_ski, g1_pow_xit)
	return sigma1_i_t
}

// computeShamirSContribution computes this user's [s]*_self = y_self * L_self(0) mod P
func (u *User) computeShamirSContribution(participantIDsForS []*big.Int) (*big.Int, error) {
	evalAtZero := big.NewInt(0)
	lagrangeCoeff, err := computeLagrangeCoefficient(evalAtZero, u.shamirShareX, participantIDsForS, u.pp.P)
	if err != nil {
		return nil, fmt.Errorf("user %d failed to compute Lagrange coefficient: %v. OwnX: %s, Participants: %v", u.ID, err, u.shamirShareX.String(), participantIDsForS)
	}

	s_contribution_bigint := new(big.Int).Mul(u.shamirShareY, lagrangeCoeff)
	s_contribution_bigint.Mod(s_contribution_bigint, u.pp.P)

	return s_contribution_bigint, nil
}

// CreatePartialSignature computes σ2,j_originator,t = ek_assigned_to_j * H1(t) + [s]*_j * σ1_originator,t
func (u *User) CreatePartialSignature(
	t_data []byte,
	sigma1_of_originatorUser_t *bn256.G1,
	ek_assigned_to_this_helper *big.Int,
	participantIDsForS []*big.Int,
) (*bn256.G1, error) {

	h1t := u.pp.H1(t_data)
	h1t_pow_ek := new(bn256.G1).ScalarMult(h1t, ek_assigned_to_this_helper) // ek * H1(t)

	s_star_j, err := u.computeShamirSContribution(participantIDsForS)
	if err != nil {
		return nil, fmt.Errorf("helper user %d creating partial sig: %v", u.ID, err)
	}
	sigma1_pow_s_star_j := new(bn256.G1).ScalarMult(sigma1_of_originatorUser_t, s_star_j) // [s]*_j * σ1_orig

	sigma2 := new(bn256.G1).Add(h1t_pow_ek, sigma1_pow_s_star_j)
	return sigma2, nil
}

// ComputeFinalUserSignature computes σ_i,t = ek_self * H1(t) + σ3_i,t + [s]*_i * σ1_i,t_original
func (u *User) ComputeFinalUserSignature(
	t_data []byte,
	sigma3_i_t *bn256.G1,
	sigma1_i_t_original *bn256.G1,
	ek_self *big.Int,
	participantIDsForS []*big.Int,
) (*bn256.G1, error) {

	h1t := u.pp.H1(t_data)
	h1t_pow_ek_self := new(bn256.G1).ScalarMult(h1t, ek_self) // ek_self * H1(t)

	s_star_i, err := u.computeShamirSContribution(participantIDsForS)
	if err != nil {
		return nil, fmt.Errorf("user %d computing final sig: %v", u.ID, err)
	}
	sigma1_original_pow_s_star_i := new(bn256.G1).ScalarMult(sigma1_i_t_original, s_star_i) // [s]*_i * σ1_orig

	sigma_i_t := new(bn256.G1).Add(h1t_pow_ek_self, sigma3_i_t)
	sigma_i_t.Add(sigma_i_t, sigma1_original_pow_s_star_i)

	return sigma_i_t, nil
}

// --- Aggregator Methods ---

// NewAggregator creates a new Aggregator instance.
func NewAggregator(pp *PublicParams, allSystemUsers []*User) *Aggregator {
	return &Aggregator{
		pp:                          pp,
		Users:                       allSystemUsers,
		userEncryptionKeyForHelpers: make(map[int]map[int]*big.Int),
		userSelfEncryptionKey:       make(map[int]*big.Int),
	}
}

// PrepareForUserISigning selects helper set Ui for originatorUser and assigns originatorUser's encryption keys.
func (agg *Aggregator) PrepareForUserISigning(originatorUserID int) (signingSetUiUserIDs []int, participantXsForS []*big.Int, err error) {
	k_helpers := agg.pp.K
	n_total_users := agg.pp.N

	if originatorUserID < 1 || originatorUserID > n_total_users {
		return nil, nil, fmt.Errorf("invalid originatorUserID: %d", originatorUserID)
	}
	originatorUser := agg.Users[originatorUserID-1]

	signingSetUiUserIDs = make([]int, 0, k_helpers)
	potentialHelperIdx := (originatorUserID - 1 + 1) % n_total_users

	// Keep track of how many loops to avoid infinite loop in unexpected scenarios, though K <= N-2 should prevent it.
	iterations := 0
	maxIterations := n_total_users

	for len(signingSetUiUserIDs) < k_helpers && iterations < maxIterations {
		currentPotentialUser := agg.Users[potentialHelperIdx]
		if currentPotentialUser.ID != originatorUserID {
			signingSetUiUserIDs = append(signingSetUiUserIDs, currentPotentialUser.ID)
		}
		potentialHelperIdx = (potentialHelperIdx + 1) % n_total_users
		iterations++
	}

	if len(signingSetUiUserIDs) < k_helpers {
		return nil, nil, fmt.Errorf("could not find enough distinct helpers (%d) for user %d (K=%d, N=%d)", len(signingSetUiUserIDs), originatorUserID, k_helpers, n_total_users)
	}

	participantXsForS = make([]*big.Int, k_helpers+1)
	participantXsForS[0] = new(big.Int).Set(originatorUser.shamirShareX)
	for i, helperID := range signingSetUiUserIDs {
		helperUser := agg.Users[helperID-1]
		participantXsForS[i+1] = new(big.Int).Set(helperUser.shamirShareX)
	}

	if len(originatorUser.EncryptionKeys) != k_helpers+1 {
		return nil, nil, fmt.Errorf("originator user %d has incorrect number of encryption keys: got %d, want %d",
			originatorUserID, len(originatorUser.EncryptionKeys), k_helpers+1)
	}

	agg.userEncryptionKeyForHelpers[originatorUserID] = make(map[int]*big.Int)
	for i := 0; i < k_helpers; i++ {
		helperID := signingSetUiUserIDs[i]
		agg.userEncryptionKeyForHelpers[originatorUserID][helperID] = originatorUser.EncryptionKeys[i]
	}
	agg.userSelfEncryptionKey[originatorUserID] = originatorUser.EncryptionKeys[k_helpers]

	return signingSetUiUserIDs, participantXsForS, nil
}

// GetEncryptionKeyForHelper retrieves the assigned encryption key for a helper.
func (agg *Aggregator) GetEncryptionKeyForHelper(originatorUserID, helperUserID int) (*big.Int, error) {
	helperKeysMap, ok := agg.userEncryptionKeyForHelpers[originatorUserID]
	if !ok {
		return nil, fmt.Errorf("no encryption key assignments found for originator %d", originatorUserID)
	}
	key, ok := helperKeysMap[helperUserID]
	if !ok {
		return nil, fmt.Errorf("no encryption key assigned to helper %d by originator %d", helperUserID, originatorUserID)
	}
	return key, nil
}

// GetSelfEncryptionKey retrieves the originator's self-encryption key.
func (agg *Aggregator) GetSelfEncryptionKey(originatorUserID int) (*big.Int, error) {
	key, ok := agg.userSelfEncryptionKey[originatorUserID]
	if !ok {
		return nil, fmt.Errorf("no self-encryption key found for originator %d", originatorUserID)
	}
	return key, nil
}

// CombinePartialSignatures computes σ3_i,t = sum_{j in Ui} σ2,j_i,t
func (agg *Aggregator) CombinePartialSignatures(partialSignatures_σ2 []*bn256.G1) *bn256.G1 {
	sigma3_i_t := new(bn256.G1) // Identity for G1 addition (point at infinity)
	for _, partialSig := range partialSignatures_σ2 {
		sigma3_i_t.Add(sigma3_i_t, partialSig)
	}
	return sigma3_i_t
}

// AggregateFinalUserSignatures computes σ_t = sum_i σ_i,t
func (agg *Aggregator) AggregateFinalUserSignatures(finalUserSignatures_σ_i_t []*bn256.G1) *bn256.G1 {
	aggregateSigma_t := new(bn256.G1) // Identity for G1 addition
	for _, userSig := range finalUserSignatures_σ_i_t {
		aggregateSigma_t.Add(aggregateSigma_t, userSig)
	}
	return aggregateSigma_t
}

// --- Verifier Methods ---

// VerifySignature checks the aggregate signature.
// e(H(t), vk1) * e(g1^sum_total_xi_t, vk2) == e(σ_t, g2)
// Additive in GT: e(H(t), vk1) + e(sum_total_xi_t * g1, vk2) == e(σ_t, g2)
func VerifySignature(
	pp *PublicParams,
	vk *VerificationKey,
	t_data []byte,
	sum_total_xi_t *big.Int,
	aggregate_sigma_t *bn256.G1,
) bool {

	ht := pp.H(t_data)
	lhs_part1 := pp.e(ht, vk.VK1) // e(H(t), VK1)

	g1_pow_sum_xit := new(bn256.G1).ScalarBaseMult(sum_total_xi_t) // sum_total_xi_t * g1
	lhs_part2 := pp.e(g1_pow_sum_xit, vk.VK2)                      // e(sum_total_xi_t * g1, VK2)

	lhs_final := new(bn256.GT).Add(lhs_part1, lhs_part2)

	rhs_final := pp.e(aggregate_sigma_t, pp.g2) // e(σ_t, g2)

	return bytes.Equal(lhs_final.Marshal(), rhs_final.Marshal())
}
