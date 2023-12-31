use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use rand::Rng;

pub struct ZKP {
    pub p: BigUint,
    pub q: BigUint,
    pub alpha: BigUint,
    pub beta: BigUint,
}

impl ZKP {
    pub fn compute_pair(&self, exp: &BigUint) -> (BigUint, BigUint) {
        let p1 = self.alpha.modpow(exp, &self.p);
        let p2 = self.beta.modpow(exp, &self.p);
        (p1, p2)
    }
    /// Performs modular exponentiation.
    ///
    /// # Arguments
    /// * `n` - The base as a BigUint reference.
    /// * `exponent` - The exponent as a BigUint reference.
    /// * `modulus` - The modulus as a BigUint reference.
    ///
    /// # Returns
    /// The result of `n` raised to the power of `exponent` modulo `modulus`.
    pub fn exponentiate(n: &BigUint, exponent: &BigUint, modulus: &BigUint) -> BigUint {
        n.modpow(exponent, modulus)
    }

    /// Computes the response for a zero-knowledge proof challenge.
    ///
    /// # Arguments

    /// * `c` - The challenge value as a BigUint reference.
    /// * `x` - The secret value as a BigUint reference.
    /// * `q` - The order of the subgroup as a BigUint reference.
    ///
    /// # Returns
    /// The response `s` calculated as `(k - c * x) mod q`.
    /// If `k < c * x`, it correctly handles the modulus of the negative result.
    pub fn response(&self, k: &BigUint, c: &BigUint, x: &BigUint) -> BigUint {
        if *k >= c * x {
            return (k - c * x).modpow(&BigUint::from(1u32), &self.q);
        }
        &self.q - (c * x - k).modpow(&BigUint::from(1u32), &self.q)
    }
    /// Verifies the correctness of a zero-knowledge proof.
    ///
    /// # Arguments
    /// * `r1` - The first value to verify, as a BigUint reference.
    /// * `r2` - The second value to verify, as a BigUint reference.
    /// * `y1` - The first public key component, as a BigUint reference.
    /// * `y2` - The second public key component, as a BigUint reference.
    /// * `alpha` - The first generator of the group, as a BigUint reference.
    /// * `beta` - The second generator of the group, as a BigUint reference.
    /// * `c` - The challenge from the verifier, as a BigUint reference.
    /// * `s` - The response from the prover, as a BigUint reference.
    /// * `p` - The modulus, as a BigUint reference.
    ///
    /// # Returns
    /// `true` if the verification conditions are met, otherwise `false`.
    pub fn verify(
        &self,
        r1: &BigUint,
        r2: &BigUint,
        y1: &BigUint,
        y2: &BigUint,
        c: &BigUint,
        s: &BigUint,
    ) -> bool {
        // Check the first condition: r1 == (alpha^s * y1^c) mod p
        let cond1 = *r1 == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p)).modpow(&BigUint::from(1u32), &self.p);
        // Check the second condition: r2 == (beta^s * y2^c) mod p
        let cond2 = *r2 == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p)) .modpow(&BigUint::from(1u32), &self.p);
        // If both conditions are true, the verification succeeds
        cond1 && cond2
    }
    /// Generates a random `BigUint` value below a specified bound.
    pub fn generate_random_below(bound: &BigUint) -> BigUint {
        let mut rng = OsRng;
        rng.gen_biguint_below(bound)
    }
    pub fn generate_random_string(size: usize) -> String {
        rand::thread_rng()
            .sample_iter(rand::distributions::Alphanumeric)
            .take(size)
            .map(char::from)
            .collect()
    }
    pub fn get_constants() -> (BigUint, BigUint, BigUint, BigUint) {
        let p_str = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        let q_str = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
        let alpha_str = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
        let exp_str = "A4D1CBD5504F213160217B46A5E90";
        //Convert strings to BigUint.
        let p = BigUint::parse_bytes(p_str.as_bytes(), 16).unwrap();
        let alpha = BigUint::parse_bytes(alpha_str.as_bytes(), 16).unwrap();
        let q = BigUint::parse_bytes(q_str.as_bytes(), 16).unwrap();
        let exp = BigUint::parse_bytes(exp_str.as_bytes(),16).unwrap();

        // Compute beta as alpha raised to a random exponent modulo p.
        let beta = alpha.modpow(&exp, &p);
        (alpha, beta, p, q)
    }
}
#[cfg(test)]
#[cfg(test)]
mod test {
    use super::*;

    /// Tests ZKP functionality with small, predefined values.
    #[test]
    fn test_toy_example_with_random_numbers() {
        // Initialize the ZKP struct with small, predefined values.
        let zkp = ZKP {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            alpha: BigUint::from(4u32),
            beta: BigUint::from(9u32),
        };

        // Generate random values for private key (x), nonce (k), and challenge (c).
        let x = ZKP::generate_random_below(&zkp.q);
        let k = ZKP::generate_random_below(&zkp.q);
        let c = ZKP::generate_random_below(&zkp.q);

        // Compute public keys (y1, y2) and commitments (r1, r2).
        let y1 = ZKP::exponentiate(&zkp.alpha, &x, &zkp.p);
        let y2 = ZKP::exponentiate(&zkp.beta, &x, &zkp.p);
        let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
        let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);

        // Compute response and verify the proof.
        let s = zkp.response(&k, &c, &x);
        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);

        // Assert the proof is valid.
        assert!(result);
    }

    /// Tests ZKP functionality using 1024-bit constants from RFC 5114.
    #[test]
    fn test_with_1024_bit_constant() {
        // Parse hexadecimal constants for p, alpha, and q as per RFC 5114.
        let p_str = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
        let q_str = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
        let g_str = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
        //Convert strings to BigUint.
        let p = BigUint::parse_bytes(p_str.as_bytes(), 16).unwrap();
        let alpha = BigUint::parse_bytes(g_str.as_bytes(), 16).unwrap();
        let q = BigUint::parse_bytes(q_str.as_bytes(), 16).unwrap();

        // Compute beta as alpha raised to a random exponent modulo p.
        let beta = alpha.modpow(&ZKP::generate_random_below(&q), &p);

        // Initialize ZKP with the large constants.
        let zkp = ZKP { p, q, alpha, beta };

        // Generate random values for private key (x), nonce (k), and challenge (c).
        let x = ZKP::generate_random_below(&zkp.q);
        let k = ZKP::generate_random_below(&zkp.q);
        let c = ZKP::generate_random_below(&zkp.q);

        // Compute public keys (y1, y2) and commitments (r1, r2).
        let y1 = ZKP::exponentiate(&zkp.alpha, &x, &zkp.p);
        let y2 = ZKP::exponentiate(&zkp.beta, &x, &zkp.p);
        let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
        let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);

        // Compute response and verify the proof.
        let s = zkp.response(&k, &c, &x);
        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);

        // Assert the proof is valid.
        assert!(result);
    }
}
