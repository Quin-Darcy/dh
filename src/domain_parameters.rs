use num_bigint::BigUint;
use num_traits::Num;


// MODP-3072 defined in RFC 3526
// const MODULUS_STR: &str = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1\
//                           29024E088A67CC74020BBEA63B139B22514A08798E3404DD\
//                           EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245\
//                           E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED\
//                           EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D\
//                           C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F\
//                           83655D23DCA3AD961C62F356208552BB9ED529077096966D\
//                           670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B\
//                           E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9\
//                           DE2BCBF6955817183995497CEA956AE515D2261898FA0510\
//                           15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64\
//                           ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7\
//                           ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B\
//                           F12FFA06D98A0864D87602733EC86A64521F2B18177B200C\
//                           BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31\
//                           43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
const MODULUS_STR: &str = "DEADBEEF";

// The generator of MODP-3072 is 2
const GENERATOR: u32 = 2_u32;

pub fn get_modulus() -> BigUint {
    BigUint::from_str_radix(MODULUS_STR, 16).expect("Invalid modulus")
}

pub fn get_generator() -> BigUint {
    BigUint::from(GENERATOR)
}

// Returns order (q) of GF(p)* where p := modulus
pub fn get_group_order() -> BigUint {
    let modulus = BigUint::from_str_radix(MODULUS_STR, 16).expect("Invalid modulus");

    // For MODP-3072, we have q = (p - 1) / 2 
    (modulus - 1_u32) / 2_u32
}
