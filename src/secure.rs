//! Winlink secure login: the gateway sends `;PQ: <challenge>`, the client
//! answers `;PR: <8 digits>` derived from MD5(challenge ‖ password ‖ salt).
//! The password itself never goes over the air.
//!
//! The algorithm is not in the published B2F document; it is documented in
//! code by paclink-unix and Pat (wl2k-go), which this matches.

use crate::md5;

const SALT: [u8; 64] = [
    77, 197, 101, 206, 190, 249, 93, 200, 51, 243, 93, 237, 71, 94, 239, 138, //
    68, 108, 70, 185, 225, 137, 217, 16, 51, 122, 193, 48, 194, 195, 198, 175, //
    172, 169, 70, 84, 61, 62, 104, 186, 114, 52, 61, 168, 66, 129, 192, 208, //
    187, 249, 232, 193, 41, 113, 41, 45, 240, 16, 29, 228, 208, 228, 61, 20,
];

pub fn login_response(challenge: &str, password: &str) -> String {
    let mut payload = Vec::with_capacity(challenge.len() + password.len() + SALT.len());
    payload.extend_from_slice(challenge.as_bytes());
    payload.extend_from_slice(password.as_bytes());
    payload.extend_from_slice(&SALT);
    let sum = md5::digest(&payload);

    let mut value = u32::from(sum[3] & 0x3f);
    for &byte in sum[..3].iter().rev() {
        value = (value << 8) | u32::from(byte);
    }
    let digits = format!("{value:08}");
    digits[digits.len() - 8..].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vectors from Pat's test suite (fbb/secure_test.go).
    #[test]
    fn matches_reference() {
        assert_eq!(login_response("23753528", "FOOBAR"), "72768415");
        assert_eq!(login_response("23753528", "FooBar"), "95074758");
    }

    #[test]
    fn always_eight_digits() {
        for challenge in ["0", "1", "99999999", "12345678"] {
            let r = login_response(challenge, "x");
            assert_eq!(r.len(), 8);
            assert!(r.bytes().all(|b| b.is_ascii_digit()));
        }
    }
}
