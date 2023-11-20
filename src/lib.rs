use num_bigint::BigUint;

/// Performs modular exponentiation.
///
/// # Arguments
/// * `n` - The base as a BigUint reference.
/// * `exponent` - The exponent as a BigUint reference.
/// * `modulus` - The modulus as a BigUint reference.
///
/// # Returns
/// The result of `n` raised to the power of `exponent` modulo `modulus`.
pub fn exponentiate(n: &BigUint, exponent: &BigUint,modulus:&BigUint)-> BigUint{
   n.modpow(exponent,modulus)
}

/// Computes the response for a zero-knowledge proof challenge.
///
/// # Arguments
/// * `k` - The random nonce as a BigUint reference.
/// * `c` - The challenge value as a BigUint reference.
/// * `x` - The secret value as a BigUint reference.
/// * `q` - The order of the subgroup as a BigUint reference.
///
/// # Returns
/// The response `s` calculated as `(k - c * x) mod q`.
/// If `k < c * x`, it correctly handles the modulus of the negative result.
pub fn response(k: &BigUint,c: &BigUint, x: &BigUint,q:&BigUint)->BigUint{
   if *k >= c*x {
      return (k-c*x)%q;
   }
   (q-(c*x-k))%q
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
pub fn verify(r1: &BigUint,r2: &BigUint, y1: &BigUint,y2:&BigUint,alpha: &BigUint,beta: &BigUint,c:&BigUint,s:&BigUint,p:&BigUint)-> bool{
   // Check the first condition: r1 == (alpha^s * y1^c) mod p
   let cond1 = r1 == alpha.modpow(s,p) * y1.modpow(c,p);
   // Check the second condition: r2 == (beta^s * y2^c) mod p
   let cond2 = r2 == beta.modpow(s,p) * y2.modpow(c,p);
   // If both conditions are true, the verification succeeds
   cond1 && cond2
}
