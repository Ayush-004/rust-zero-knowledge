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
pub fn response(k: &BigUint, c: &BigUint, x: &BigUint, q: &BigUint) -> BigUint {
   // First, ensure c * x is within the modulus
   let c_x_mod_q = (c * x) % q;

   // Now add q to k, and then perform the subtraction and modulus
   let k_plus_q = k + q;
   (k_plus_q - c_x_mod_q) % q
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
   let cond1 = *r1 == (alpha.modpow(s,p) * y1.modpow(c,p))%p;
   // Check the second condition: r2 == (beta^s * y2^c) mod p
   let cond2 = *r2 == (beta.modpow(s,p) * y2.modpow(c,p))%p;
   // If both conditions are true, the verification succeeds
   cond1 && cond2
}
#[cfg(test)]
mod test{
   use super::*;
   #[test]
   fn test_toy_example(){
      let alpha = BigUint::from(4u32);
      let beta = BigUint::from(9u32);
      let p = BigUint::from(23u32);
      let q = BigUint::from(11u32);
      let x = BigUint::from(6u32);
      let k = BigUint::from(7u32);
      let c= BigUint::from(4u32);
      let y1 = exponentiate(&alpha,&x,&p);
      let y2 = exponentiate(&beta,&x,&p);
      assert_eq!(y1,BigUint::from(2u32));
      assert_eq!(y2,BigUint::from(3u32));

      let r1 = exponentiate(&alpha,&k,&p);
      let r2 = exponentiate(&beta,&k,&p);
      assert_eq!(r1,BigUint::from(8u32));
      assert_eq!(r2,BigUint::from(4u32));

      let s = response(&k,&c,&x,&q);
      assert_eq!(s,BigUint::from(5u32));

      let result = verify(&r1,&r2,&y1,&y2,&alpha,&beta,&c,&s,&p);
      assert!(result);
   }
}