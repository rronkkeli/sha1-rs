//! This is my (rronkkeli's) implementation of Secure Hash Algorithm.
//! You may use this implementation as you please for your needs.
//! Test hashes have been calculated with third party hashing tools
//! like the ones that come with 7-zip.

use std::{fs::File, io::{self, Read, Seek}};

pub struct SHA1 {
    h0: u32,
    h1: u32,
    h2: u32,
    h3: u32,
    h4: u32,
}

impl SHA1 {
    const K: [u32; 4] = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];

    // Initializes the hash
    fn new() -> Self {
        Self {
            h0: 0x67452301,
            h1: 0xefcdab89,
            h2: 0x98badcfe,
            h3: 0x10325476,
            h4: 0xc3d2e1f0,
        }
    }

    // Should not be used with large files as it takes up too much memory.
    // Can be used with small files though.
    fn hash_sha1(mut message: Vec<u8>) -> Self {
        let mut h: SHA1 = Self::new();
        // Preprocessing the message
        // Calculate message length in bits and convert it into bytes
        let len: [u8; 8] = ((message.len() * 8) as u64).to_be_bytes();

        // Add bit 1 in the end of the message
        // Because we are working with bytes and padding with zeroes anyway,
        // this is the same as adding byte 0x80
        message.push(0x80);

        // Pad with zeroes until the last block is 448 bits (56 bytes) long
        while message.len() % 64 != 56 {
            message.push(0);
        }

        // Append the length of the original message in big endian order
        for byte in len {
            message.push(byte);
        }

        // Length of the entire message should now be a multiple of 512 (64 bytes)
        assert!(message.len() % 64 == 0);

        // Amount of blocks
        let blocks: usize = message.len() / 64;

        // Process the blocks
        for b in 0..blocks {
            let range = (b * 64)..((b + 1) * 64);
            let block_bytes = message[range].to_vec();

            h.hash_block(block_bytes);
        }

        h
    }

    /// Hashes entire file contents while not consuming memory too much.
    /// Works with large files too.
    pub fn hash_sha1_file(file: &mut File) -> Result<Self, io::Error> {
        let blen: u64 = file.metadata()?.len() as u64;
        let len: [u8; 8] = (blen * 8).to_be_bytes();
        let mut h: SHA1 = SHA1::new();

        // Count whole 512-bit blocks
        let whole_blocks = blen / 64;

        // Count the left over byte amount
        let left_over = blen % 64;

        // Create last block(s)
        // There is a possibility that there will be 2 blocks added
        let mut last_blocks: Vec<u8> = Vec::new();

        // Read last bytes from file to last_blocks
        file.seek(io::SeekFrom::Start(whole_blocks * 64))?;
        let bytes_read = file.read_to_end(&mut last_blocks)?;

        assert!(bytes_read == left_over as usize);

        // Append bit '1'
        last_blocks.push(0x80);
        
        // Pad with zeroes
        while (last_blocks.len() % 64) != 56 {
            last_blocks.push(0);
        }
        
        // Append with bit length
        for byte in len {
            last_blocks.push(byte);
        }

        assert!(last_blocks.len() % 64 == 0);
        
        // Return file cursor into the beginning of the file
        file.seek(io::SeekFrom::Start(0))?;

        // Hash the whole blocks from the file directly.
        // The file cursor should move automatically after every read.
        for _ in 0..whole_blocks {
            let block_bytes: Vec<u8> = {
                let mut buf: [u8; 64] = [0; 64];
                file.read_exact(&mut buf)?;

                buf.to_vec()
            };

            h.hash_block(block_bytes);
        }

        // Last we hash the last blocks
        for b in 0..(last_blocks.len() / 64) {
            let range = b * 64..(b + 1) * 64;
            let block_bytes: Vec<u8> = last_blocks[range].to_vec();

            h.hash_block(block_bytes);
        }

        // Return the hash
        Ok(h)
    }

    /// Convert SHA1 to lowercase hexadecimal string
    pub fn to_lhex(self) -> String {
        let mut hex: String = String::new();

        hex.push_str(format!("{:08x}", self.h0).as_str());
        hex.push_str(format!("{:08x}", self.h1).as_str());
        hex.push_str(format!("{:08x}", self.h2).as_str());
        hex.push_str(format!("{:08x}", self.h3).as_str());
        hex.push_str(format!("{:08x}", self.h4).as_str());

        hex
    }

    /// Convert SHA1 to uppercase hexadecimal string
    pub fn to_uhex(self) -> String {
        let mut hex: String = String::new();

        hex.push_str(format!("{:08X}", self.h0).as_str());
        hex.push_str(format!("{:08X}", self.h1).as_str());
        hex.push_str(format!("{:08X}", self.h2).as_str());
        hex.push_str(format!("{:08X}", self.h3).as_str());
        hex.push_str(format!("{:08X}", self.h4).as_str());

        hex
    }

    fn hash_block(&mut self, block: Vec<u8>) {
        let mut words: Vec<u32> = Vec::new();

        // Initialize working variables
        let mut a: u32 = self.h0;
        let mut b: u32 = self.h1;
        let mut c: u32 = self.h2;
        let mut d: u32 = self.h3;
        let mut e: u32 = self.h4;

        // Convert the bytes in the block into words
        for i in 0..16 {
            let range = (i * 4)..((i + 1) * 4);
            let word: u32 = {
                let mut wbuf: [u8; 4] = [0; 4];
                wbuf.clone_from_slice(&block[range]);
                u32::from_be_bytes(wbuf)
            };

            words.push(word);
        }

        // Check that the words list is exactly 16 words long at this point to catch possible errors
        assert!(words.len() == 16);

        // Extend the words from 16 words to 80 words aka prepare message schedule
        for i in 16..80 {
            let w: u32 =
                (words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16]).rotate_left(1);
            words.push(w);
        }

        // Assert that the message schedule is 80 words
        assert!(words.len() == 80);

        // Process the message schedule
        for t in 0..80 {
            let k: u32;
            let f: u32;
            let w: u32 = words[t];

            match t / 20 {
                // 0 <= t <= 19
                0 => {
                    f = (b & c) ^ (!b & d);
                    k = Self::K[0];
                }

                // 20 <= t <= 39
                1 => {
                    f = b ^ c ^ d;
                    k = Self::K[1];
                }

                // 40 <= t <= 59
                2 => {
                    f = (b & c) ^ (b & d) ^ (c & d);
                    k = Self::K[2];
                }

                // 60 <= t <= 79
                3 => {
                    f = b ^ c ^ d;
                    k = Self::K[3];
                }

                _ => {
                    // This arm will always be inaccessable but let's panic for fun
                    panic!("Divident ({t}) not expected!");
                }
            }

            // Calculate temporary value
            let temp: u32 = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(w);

            // Finally update working variables
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }

        // Update hash values before proceeding to next block or ending the hashing
        self.h0 = a.wrapping_add(self.h0);
        self.h1 = b.wrapping_add(self.h1);
        self.h2 = c.wrapping_add(self.h2);
        self.h3 = d.wrapping_add(self.h3);
        self.h4 = e.wrapping_add(self.h4);
    }
}

pub trait HashSHA1 {
    fn sha1(&self) -> SHA1;
}

impl HashSHA1 for String {
    fn sha1(&self) -> SHA1 {
        let msg: Vec<u8> = self.clone().into_bytes();
        SHA1::hash_sha1(msg)
    }
}

impl HashSHA1 for str {
    fn sha1(&self) -> SHA1 {
        let msg: Vec<u8> = self.as_bytes().to_vec();
        SHA1::hash_sha1(msg)
    }
}

impl HashSHA1 for [u8] {
    fn sha1(&self) -> SHA1 {
        let msg: Vec<u8> = self.to_vec();
        SHA1::hash_sha1(msg)
    }
}

impl HashSHA1 for &[u8] {
    fn sha1(&self) -> SHA1 {
        let msg: Vec<u8> = self.to_vec();
        SHA1::hash_sha1(msg)
    }
}

impl HashSHA1 for Vec<u8> {
    fn sha1(&self) -> SHA1 {
        SHA1::hash_sha1(self.clone())
    }
}

#[test]
fn test_hash0() {
    let data = "abcdefg";
    let hash_str = data.sha1().to_lhex();
    let compare_str: String = String::from("2fb5e13419fc89246865e7a324f476ec624e8740");

    assert_eq!(hash_str, compare_str);
}

#[test]
fn test_hash1() {
    let data = "1234567890";
    let hash_str = data.sha1().to_lhex();
    let compare_str: String = String::from("01b307acba4f54f55aafc33bb06bbbf6ca803e9a");

    assert_eq!(hash_str, compare_str);
}

#[test]
fn test_file_hash0() -> Result<(), io::Error> {
    let mut file: File = File::open("test.txt")?;
    let hash_str: String = SHA1::hash_sha1_file(&mut file)?.to_lhex();
    let compare_str: String = String::from("94f66bfc3b2ce354a431097ee708d7e92d0a9a00");

    assert_eq!(hash_str, compare_str);

    Ok(())
}

#[test]
fn test_file_hash1() -> Result<(), io::Error> {
    let hash_str: String = {
        let mut file: File = File::open("test.txt")?;
        let mut buf: Vec<u8> = Vec::new();
        file.read_to_end(&mut buf)?;
        
        buf.sha1().to_lhex()
    };

    let compare_str: String = String::from("94f66bfc3b2ce354a431097ee708d7e92d0a9a00");

    assert_eq!(hash_str, compare_str);

    Ok(())
}