use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;

pub struct ZKP {
    p: BigUint,
    q: BigUint,
    alpha: BigUint,
    beta: BigUint,
}

impl ZKP {
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
        // First, ensure c * x is within the modulus
        let c_x_mod_q = (c * x) % &self.q;

        let k_plus_q = k + &self.q;
        (k_plus_q - c_x_mod_q) % &self.q
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
        let cond1 = *r1 == (&self.alpha.modpow(s, &self.p) * y1.modpow(c, &self.p)) % &self.p;
        // Check the second condition: r2 == (beta^s * y2^c) mod p
        let cond2 = *r2 == (&self.beta.modpow(s, &self.p) * y2.modpow(c, &self.p)) % &self.p;
        // If both conditions are true, the verification succeeds
        cond1 && cond2
    }
    /// Generates a random `BigUint` value below a specified bound.
    pub fn generate_random_below(bound: &BigUint) -> BigUint {
        let mut rng = OsRng;
        rng.gen_biguint_below(bound)
    }
}
#[cfg(test)]
mod test {
    /// Test module for validating the cryptographic functions in a simulated environment.
    /// This test uses randomly generated values for nonce and challenge to simulate a
    /// zero-knowledge proof scenario.
    use super::*;
    #[test]
    fn test_toy_example_with_random_numbers() {
        let zkp = ZKP {
            p: BigUint::from(23u32),
            q: BigUint::from(11u32),
            alpha: BigUint::from(4u32),
            beta: BigUint::from(9u32),
        };
        let alpha = BigUint::from(4u32);
        let beta = BigUint::from(9u32);
        let p = BigUint::from(23u32);
        let q = BigUint::from(11u32);
        let x = BigUint::from(6u32);
        let k = ZKP::generate_random_below(&zkp.q);
        let c = ZKP::generate_random_below(&zkp.q);
        let y1 = ZKP::exponentiate(&zkp.alpha, &x, &zkp.p);
        let y2 = ZKP::exponentiate(&zkp.beta, &x, &zkp.p);
        assert_eq!(y1, BigUint::from(2u32));
        assert_eq!(y2, BigUint::from(3u32));

        let r1 = ZKP::exponentiate(&zkp.alpha, &k, &zkp.p);
        let r2 = ZKP::exponentiate(&zkp.beta, &k, &zkp.p);

        let s = zkp.response(&k, &c, &x);

        let result = zkp.verify(&r1, &r2, &y1, &y2, &c, &s);
        assert!(result);
    }
}
