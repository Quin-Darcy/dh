mod domain_parameters;

use domain_parameters::{get_modulus, get_group_order, get_generator};
use rand::thread_rng;
use num_traits::{Zero, One};
use num_bigint::{BigUint, RandBigInt};
use bitvec::prelude::*;


fn to_binary(num: &BigUint) -> BitVec {
    let mut bits = BitVec::new();
    let mut mask = BigUint::one();
    while mask <= *num {
        bits.push(if num & &mask > BigUint::zero() { true } else { false });
        mask <<= 1;
    }
    bits.reverse();
    bits
}

// Employs the Square-and-Multiply technique to compute g ^ a (mod p)
fn mod_exp(base: &BigUint, exp: &BigUint, modulus: &BigUint) -> BigUint {
    let exp_bin_rep = to_binary(exp);
    let mut product = BigUint::one();
    let mut current_square = base.clone();

    for bit in exp_bin_rep.iter().rev() {
        if *bit {
            product = &product * &current_square % modulus;
        }
        current_square = &current_square * &current_square % modulus;
    }

    product
}

// Returns random integer in range [1, q - 1]
fn get_private_key() -> BigUint {
    let mut rng = thread_rng();
    rng.gen_biguint_range(&BigUint::from(1_u32), &get_group_order())
}

// Public key is computed as (generator) ^ (private key) (mod modulus)
fn get_public_key(private_key: &BigUint) -> BigUint {
    mod_exp(&get_generator(), private_key, &get_modulus())
}

// To be used once we have received the other party's public key
pub fn get_secret(public_key: &BigUint, private_key: &BigUint, modulus: &BigUint) -> BigUint {
    mod_exp(public_key, private_key, modulus)
}

// Returns (private key, public key) tuple
pub fn gen_key_pair() -> (BigUint, BigUint) {
    let private_key = get_private_key();
    let public_key = get_public_key(&private_key);
    (private_key, public_key)
}


// TODO: Add unit testing and bench marks