#![feature(test)]

#[cfg(test)]
extern crate test;

// BLAKE2: simpler, smaller, fast as MD5
// https://www.blake2.net/blake2.pdf
// 
// The BLAKE2 Cryptographic Hash and Message Authentication Code (MAC)
// https://datatracker.ietf.org/doc/html/rfc7693
// 
// BLAKE2 comes in two basic flavors:
// 
//     o  BLAKE2b (or just BLAKE2) is optimized for 64-bit platforms and
//        produces digests of any size between 1 and 64 bytes.
// 
//     o  BLAKE2s is optimized for 8- to 32-bit platforms and produces
//        digests of any size between 1 and 32 bytes.
// 
// Both BLAKE2b and BLAKE2s are believed to be highly secure and perform
// well on any platform, software, or hardware.  BLAKE2 does not require
// a special "HMAC" (Hashed Message Authentication Code) construction
// for keyed message authentication as it has a built-in keying mechanism.
// 
// 
// 2.1.  Parameters
// https://datatracker.ietf.org/doc/html/rfc7693#section-2.1
// 
//    The following table summarizes various parameters and their ranges:
// 
//                             | BLAKE2b          | BLAKE2s          |
//               --------------+------------------+------------------+
//                Bits in word | w = 64           | w = 32           |
//                Rounds in F  | r = 12           | r = 10           |
//                Block bytes  | bb = 128         | bb = 64          |
//                Hash bytes   | 1 <= nn <= 64    | 1 <= nn <= 32    |
//                Key bytes    | 0 <= kk <= 64    | 0 <= kk <= 32    |
//                Input bytes  | 0 <= ll < 2**128 | 0 <= ll < 2**64  |
//               --------------+------------------+------------------+
//                G Rotation   | (R1, R2, R3, R4) | (R1, R2, R3, R4) |
//                 constants = | (32, 24, 16, 63) | (16, 12,  8,  7) |
//               --------------+------------------+------------------+
const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179, 
];


const fn iv_gen(hlen: u8, klen: u8) -> [u64; 8] {
    let p1 = u64::from_le_bytes([
        hlen, klen, 1, 1, // digest_length, key_length, fanout, depth
        0, 0, 0, 0,       // leaf_length
    ]);

    // IV XOR ParamBlock
    let s1 = BLAKE2B_IV[0] ^ p1;
    let state: [u64; 8] = [
        // H
        s1,          BLAKE2B_IV[1], 
        BLAKE2B_IV[2], BLAKE2B_IV[3],
        BLAKE2B_IV[4], BLAKE2B_IV[5], 
        BLAKE2B_IV[6], BLAKE2B_IV[7],
    ];

    state
}

const BLAKE2B_256_IV: [u64; 8] = iv_gen(32, 0);
const BLAKE2B_512_IV: [u64; 8] = iv_gen(64, 0);


const SIGMA: [[u8; 16]; 12] = [
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
    [ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 ],
    [  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 ],
    [  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 ],
    [  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 ],
    [ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 ],
    [ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 ],
    [  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 ],
    [ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 ],
    [  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 ],
    [ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 ],
];


macro_rules! G {
    ($a:expr, $b:expr, $c:expr, $d:expr, $mx:expr, $my:expr) => {
        $a = $a.wrapping_add($b).wrapping_add($mx);
        $d = ($d ^ $a).rotate_right(32); // R1

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(24); // R2

        $a = $a.wrapping_add($b).wrapping_add($my);
        $d = ($d ^ $a).rotate_right(16); // R3

        $c = $c.wrapping_add($d);
        $b = ($b ^ $c).rotate_right(63); // R4
    }
}

macro_rules! ROUND {
    ($state:expr, $m:expr, $sigma:expr) => {
        G!($state[ 0], $state[ 4], $state[ 8], $state[12],  $m[$sigma[ 0] as usize], $m[$sigma[ 1] as usize]);
        G!($state[ 1], $state[ 5], $state[ 9], $state[13],  $m[$sigma[ 2] as usize], $m[$sigma[ 3] as usize]);
        G!($state[ 2], $state[ 6], $state[10], $state[14],  $m[$sigma[ 4] as usize], $m[$sigma[ 5] as usize]);
        G!($state[ 3], $state[ 7], $state[11], $state[15],  $m[$sigma[ 6] as usize], $m[$sigma[ 7] as usize]);
        
        G!($state[ 0], $state[ 5], $state[10], $state[15],  $m[$sigma[ 8] as usize], $m[$sigma[ 9] as usize]);
        G!($state[ 1], $state[ 6], $state[11], $state[12],  $m[$sigma[10] as usize], $m[$sigma[11] as usize]);
        G!($state[ 2], $state[ 7], $state[ 8], $state[13],  $m[$sigma[12] as usize], $m[$sigma[13] as usize]);
        G!($state[ 3], $state[ 4], $state[ 9], $state[14],  $m[$sigma[14] as usize], $m[$sigma[15] as usize]);
    }
}



#[inline]
fn transform(state: &mut [u64; 8], block: &[u8], counter: u64, flags: u64) {
    debug_assert_eq!(state.len(), 8);
    debug_assert_eq!(block.len(), Blake2b::BLOCK_LEN);

    let mut m = [0u64; 16];
    let mut v = [0u64; 16];

    let data = block;
    m[ 0] = u64::from_le_bytes([block[ 0], block[ 1], block[ 2], block[ 3], block[ 4], block[ 5], block[ 6], block[ 7]]);
    m[ 1] = u64::from_le_bytes([block[ 8], block[ 9], block[10], block[11], block[12], block[13], block[14], block[15]]);
    m[ 2] = u64::from_le_bytes([block[16], block[17], block[18], block[19], block[20], block[21], block[22], block[23]]);
    m[ 3] = u64::from_le_bytes([block[24], block[25], block[26], block[27], block[28], block[29], block[30], block[31]]);
    
    let block = &data[32..64];
    m[ 4] = u64::from_le_bytes([block[ 0], block[ 1], block[ 2], block[ 3], block[ 4], block[ 5], block[ 6], block[ 7]]);
    m[ 5] = u64::from_le_bytes([block[ 8], block[ 9], block[10], block[11], block[12], block[13], block[14], block[15]]);
    m[ 6] = u64::from_le_bytes([block[16], block[17], block[18], block[19], block[20], block[21], block[22], block[23]]);
    m[ 7] = u64::from_le_bytes([block[24], block[25], block[26], block[27], block[28], block[29], block[30], block[31]]);
    
    let block = &data[64..96];
    m[ 8] = u64::from_le_bytes([block[ 0], block[ 1], block[ 2], block[ 3], block[ 4], block[ 5], block[ 6], block[ 7]]);
    m[ 9] = u64::from_le_bytes([block[ 8], block[ 9], block[10], block[11], block[12], block[13], block[14], block[15]]);
    m[10] = u64::from_le_bytes([block[16], block[17], block[18], block[19], block[20], block[21], block[22], block[23]]);
    m[11] = u64::from_le_bytes([block[24], block[25], block[26], block[27], block[28], block[29], block[30], block[31]]);

    let block = &data[96..128];
    m[12] = u64::from_le_bytes([block[ 0], block[ 1], block[ 2], block[ 3], block[ 4], block[ 5], block[ 6], block[ 7]]);
    m[13] = u64::from_le_bytes([block[ 8], block[ 9], block[10], block[11], block[12], block[13], block[14], block[15]]);
    m[14] = u64::from_le_bytes([block[16], block[17], block[18], block[19], block[20], block[21], block[22], block[23]]);
    m[15] = u64::from_le_bytes([block[24], block[25], block[26], block[27], block[28], block[29], block[30], block[31]]);
    
    // let t1 = (counter >> 64) as u64;
    // let t0 = counter as u64;
    // let f1 = (flags >> 64) as u64;
    // let f0 = flags as u64;
    
    #[allow(unused_variables)]
    let t1 = 0;
    let t0 = counter;
    #[allow(unused_variables)]
    let f1 = 0;
    let f0 = flags;

    v[..8].copy_from_slice(&state[..]);

    v[ 8] = BLAKE2B_IV[0];
    v[ 9] = BLAKE2B_IV[1];
    v[10] = BLAKE2B_IV[2];
    v[11] = BLAKE2B_IV[3];

    v[12] = BLAKE2B_IV[4] ^ t0;
    v[13] = BLAKE2B_IV[5] ^ t1;
    v[14] = BLAKE2B_IV[6] ^ f0;
    v[15] = BLAKE2B_IV[7] ^ f1;

    // v[12] = BLAKE2B_IV[4] ^ t0;
    // v[13] = BLAKE2B_IV[5];
    // v[14] = BLAKE2B_IV[6] ^ f0;
    // v[15] = BLAKE2B_IV[7];
    
    // 12 Rounds
    ROUND!(v, m, SIGMA[0]);
    ROUND!(v, m, SIGMA[1]);
    ROUND!(v, m, SIGMA[2]);
    ROUND!(v, m, SIGMA[3]);
    ROUND!(v, m, SIGMA[4]);
    ROUND!(v, m, SIGMA[5]);
    ROUND!(v, m, SIGMA[6]);
    ROUND!(v, m, SIGMA[7]);
    ROUND!(v, m, SIGMA[8]);
    ROUND!(v, m, SIGMA[9]);

    ROUND!(v, m, SIGMA[10]);
    ROUND!(v, m, SIGMA[11]);

    state[0] = state[0] ^ v[0] ^ v[ 8];
    state[1] = state[1] ^ v[1] ^ v[ 9];
    state[2] = state[2] ^ v[2] ^ v[10];
    state[3] = state[3] ^ v[3] ^ v[11];
    state[4] = state[4] ^ v[4] ^ v[12];
    state[5] = state[5] ^ v[5] ^ v[13];
    state[6] = state[6] ^ v[6] ^ v[14];
    state[7] = state[7] ^ v[7] ^ v[15];
}


/// BLAKE2b
#[derive(Clone)]
pub struct Blake2b {
    buffer: [u8; Self::BLOCK_LEN],
    offset: usize,
    state: [u64; 8],
    // counter: u128, // T0, T1
    counter: u64, // T0, T1
}

impl Blake2b {
    pub const BLOCK_LEN: usize  = 128;
    
    pub const H_MIN: usize =  1;
    pub const H_MAX: usize = 64;
    
    pub const K_MIN: usize =  0;
    pub const K_MAX: usize = 64;

    pub const M_MIN: u128 = 0;
    pub const M_MAX: u128 = u128::MAX;

    pub const ROUNDS: usize = 12; // Rounds in F


    #[inline]
    pub fn new(iv:[u64; 8], key: &[u8]) -> Self {
        let klen = key.len();

        assert!(klen >= Self::K_MIN && klen <= Self::K_MAX);

        let mut offset = 0usize;
        let mut block = [0u8; Self::BLOCK_LEN];
        if klen > 0 {
            offset = klen;
            block[..klen].copy_from_slice(&key);
        }

        Self {
            buffer: block,
            offset,
            state: iv,
            counter: 0
        }
    }

    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        let mut i = 0usize;
        while i < data.len() {
            if self.offset == Self::BLOCK_LEN {
                self.counter = self.counter.wrapping_add(Self::BLOCK_LEN as _);
                transform(&mut self.state, &self.buffer, self.counter, 0);
                self.offset = 0;
            }

            if self.offset < Self::BLOCK_LEN {
                self.buffer[self.offset] = data[i];
                self.offset += 1;
                i += 1;
            }
        }
    }

    #[inline]
    pub fn finalize(mut self) -> [u8; Self::H_MAX] {
        self.counter = self.counter.wrapping_add(self.offset as _);

        // Padding
        while self.offset < Self::BLOCK_LEN {
            self.buffer[self.offset] = 0;
            self.offset += 1;
        }

        transform(&mut self.state, &self.buffer, self.counter, u64::MAX);

        let mut hash = [0u8; Self::H_MAX]; // 64
        hash[ 0.. 8].copy_from_slice(&self.state[0].to_le_bytes());
        hash[ 8..16].copy_from_slice(&self.state[1].to_le_bytes());
        hash[16..24].copy_from_slice(&self.state[2].to_le_bytes());
        hash[24..32].copy_from_slice(&self.state[3].to_le_bytes());
        hash[32..40].copy_from_slice(&self.state[4].to_le_bytes());
        hash[40..48].copy_from_slice(&self.state[5].to_le_bytes());
        hash[48..56].copy_from_slice(&self.state[6].to_le_bytes());
        hash[56..64].copy_from_slice(&self.state[7].to_le_bytes());

        hash
    }
}

/// BLAKE2b-256
pub fn blake2b_256<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
    let data = data.as_ref();
    let ilen = data.len();

    let mut state   = BLAKE2B_256_IV;
    let mut counter = 0u64;
    
    let mut rlen = ilen;
    let mut ptr = data.as_ptr();

    while rlen > Blake2b::BLOCK_LEN {
        let block = unsafe { core::slice::from_raw_parts(ptr, Blake2b::BLOCK_LEN) };
        counter = counter.wrapping_add(Blake2b::BLOCK_LEN as _);
        transform(&mut state, block, counter, 0);
        ptr = unsafe { ptr.add(Blake2b::BLOCK_LEN) };
        rlen -= Blake2b::BLOCK_LEN;
    }

    let mut last_block = [0u8; Blake2b::BLOCK_LEN];
    if rlen > 0 {
        let rem = unsafe { core::slice::from_raw_parts(ptr, rlen) };
        last_block[..rlen].copy_from_slice(rem);
    }

    counter = counter.wrapping_add(rlen as _);
    transform(&mut state, &last_block, counter, u64::MAX);

    let mut hash = [0u8; Blake2b::H_MAX / 2]; // 32
    hash[ 0.. 8].copy_from_slice(&state[0].to_le_bytes());
    hash[ 8..16].copy_from_slice(&state[1].to_le_bytes());
    hash[16..24].copy_from_slice(&state[2].to_le_bytes());
    hash[24..32].copy_from_slice(&state[3].to_le_bytes());

    hash
}

/// BLAKE2b-256
pub fn blake2b_512<T: AsRef<[u8]>>(data: T) -> [u8; 64] {
    let data = data.as_ref();
    let ilen = data.len();

    let mut state   = BLAKE2B_512_IV;
    let mut counter = 0u64;
    
    let mut rlen = ilen;
    let mut ptr = data.as_ptr();

    while rlen > Blake2b::BLOCK_LEN {
        let block = unsafe { core::slice::from_raw_parts(ptr, Blake2b::BLOCK_LEN) };
        counter = counter.wrapping_add(Blake2b::BLOCK_LEN as _);
        transform(&mut state, block, counter, 0);
        ptr = unsafe { ptr.add(Blake2b::BLOCK_LEN) };
        rlen -= Blake2b::BLOCK_LEN;
    }

    let mut last_block = [0u8; Blake2b::BLOCK_LEN];
    if rlen > 0 {
        let rem = unsafe { core::slice::from_raw_parts(ptr, rlen) };
        last_block[..rlen].copy_from_slice(rem);
    }

    counter = counter.wrapping_add(rlen as _);
    transform(&mut state, &last_block, counter, u64::MAX);

    let mut hash = [0u8; Blake2b::H_MAX]; // 64
    hash[ 0.. 8].copy_from_slice(&state[0].to_le_bytes());
    hash[ 8..16].copy_from_slice(&state[1].to_le_bytes());
    hash[16..24].copy_from_slice(&state[2].to_le_bytes());
    hash[24..32].copy_from_slice(&state[3].to_le_bytes());
    hash[32..40].copy_from_slice(&state[4].to_le_bytes());
    hash[40..48].copy_from_slice(&state[5].to_le_bytes());
    hash[48..56].copy_from_slice(&state[6].to_le_bytes());
    hash[56..64].copy_from_slice(&state[7].to_le_bytes());

    hash
}


    


#[cfg(test)]
mod blake2b_xxx {
    use super::Blake2b;
    use super::blake2b_256;


    #[bench]
    pub fn blake2b_256_one_block(b: &mut test::Bencher) {
        let data = test::black_box([3u8; Blake2b::BLOCK_LEN]);
        
        b.bytes = data.len() as _;
        b.iter(|| {
            blake2b_256(data)
        })
    }

    #[bench]
    pub fn blake2b_256_32block(b: &mut test::Bencher) {
        let data = test::black_box([3u8; Blake2b::BLOCK_LEN * 32]); // 32 * 128 = 4K
        
        b.bytes = data.len() as _;
        b.iter(|| {
            blake2b_256(data)
        })
    }
}


#[cfg(test)]
mod blake2b_rfc {
    use blake2_rfc::blake2b::Blake2b;


    pub fn blake2b_256<T: AsRef<[u8]>>(data: T) -> [u8; 32] {
        let mut context = Blake2b::new(32);
        context.update(data.as_ref());
        let hash = context.finalize();

        let mut out = [0u8; 32];
        out.copy_from_slice(hash.as_bytes());

        out
    }

    #[bench]
    pub fn blake2b_256_one_block(b: &mut test::Bencher) {
        let data = test::black_box([3u8; super::Blake2b::BLOCK_LEN]);
        
        b.bytes = data.len() as _;
        b.iter(|| {
            blake2b_256(data)
        })
    }

    #[bench]
    pub fn blake2b_256_32block(b: &mut test::Bencher) {
        let data = test::black_box([3u8; super::Blake2b::BLOCK_LEN * 32]); // 32 * 128 = 4K
        
        b.bytes = data.len() as _;
        b.iter(|| {
            blake2b_256(data)
        })
    }
}
