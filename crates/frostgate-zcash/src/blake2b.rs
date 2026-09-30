//! Minimal BLAKE2b-256 with 16-byte personalization, for ZIP-243.
//!
//! Pure Rust, no dependencies. Verified against Python hashlib.blake2b.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);

    v[12] ^= (t & 0xffff_ffff_ffff_ffff) as u64;
    v[13] ^= ((t >> 64) & 0xffff_ffff_ffff_ffff) as u64;
    if last {
        v[14] ^= 0xffff_ffff_ffff_ffff;
    }

    let mut m = [0u64; 16];
    for i in 0..16 {
        m[i] = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    for r in 0..12 {
        let s = SIGMA[r % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b-256 with 16-byte personalization.
pub fn blake2b_256_personal(personal: &[u8; 16], data: &[u8]) -> [u8; 32] {
    // Parameter block: digest_length=32, key_length=0, fanout=1, depth=1,
    // leaf_length=0, node_offset=0, node_depth=0, inner_length=0,
    // salt=[0;16], personal=personal
    let mut param = [0u8; 64];
    param[0] = 32; // digest length
    param[2] = 1; // fanout
    param[3] = 1; // depth
    // salt (16 bytes at offset 32) stays zero
    param[48..64].copy_from_slice(personal);

    let mut h = [0u64; 8];
    for i in 0..8 {
        let p = u64::from_le_bytes(param[i * 8..(i + 1) * 8].try_into().unwrap());
        h[i] = IV[i] ^ p;
    }

    let mut t: u128 = 0;
    let mut pos = 0;
    while pos < data.len() {
        let remaining = data.len() - pos;
        let take = remaining.min(128);
        let mut block = [0u8; 128];
        block[..take].copy_from_slice(&data[pos..pos + take]);
        t += take as u128;
        let last = pos + take >= data.len();
        compress(&mut h, &block, t, last);
        pos += take;
    }
    // Handle empty input (single empty block)
    if data.is_empty() {
        let block = [0u8; 128];
        compress(&mut h, &block, 0, true);
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_hashlib() {
        // python3 -c "import hashlib;
        // h=hashlib.blake2b(b'hello', digest_size=32, person=b'1234567890123456');
        // print(h.hexdigest())"
        // -> 1cec991a1ce5191f727fd591c6d57fb3883c3151135dc5ec4a6f5311969feb4a
        let h = blake2b_256_personal(b"1234567890123456", b"hello");
        let expected = [
            0x1c, 0xec, 0x99, 0x1a, 0x1c, 0xe5, 0x19, 0x1f, 0x72, 0x7f, 0xd5, 0x91, 0xc6,
            0xd5, 0x7f, 0xb3, 0x88, 0x3c, 0x31, 0x51, 0x13, 0x5d, 0xc5, 0xec, 0x4a,
            0x6f, 0x53, 0x11, 0x96, 0x9f, 0xeb, 0x4a,
        ];
        assert_eq!(h, expected);
    }
}
