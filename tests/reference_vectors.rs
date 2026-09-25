//! Compatibility with the reference (JNOS-derived) LZHUF encoder.
//!
//! `gettysburg.txt.lzh` comes from Pat's test suite (wl2k-go, MIT), produced
//! by the encoder Winlink programs have used for decades.

use b2fmsg::lzhuf;

#[test]
fn decodes_reference_stream() {
    let plain = include_bytes!("data/gettysburg.txt");
    let packed = include_bytes!("data/gettysburg.txt.lzh");
    assert_eq!(lzhuf::decode_b2(packed).unwrap(), plain);
}

#[test]
fn our_stream_is_no_larger_than_reference() {
    let plain = include_bytes!("data/gettysburg.txt");
    let reference = include_bytes!("data/gettysburg.txt.lzh");
    let ours = lzhuf::encode_b2(plain);
    assert!(
        ours.len() <= reference.len(),
        "{} > {}",
        ours.len(),
        reference.len()
    );
    assert_eq!(lzhuf::decode_b2(&ours).unwrap(), plain);
}
