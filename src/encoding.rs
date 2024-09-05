use std::{fmt::Write, num::ParseIntError};

const MAXUINT6: usize = 1 << 6 - 1;
//const MAXUINT8: usize = 1 << 8 - 1;
const MAXUINT14: usize = 1 << 14 - 1;
//const MAXUINT16: usize = 1 << 16 - 1;
const MAXUINT30: usize = 1 << 30 - 1;

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn encode_usize(val: usize) -> Vec<u8> {
    match val {
        val if val <= MAXUINT6 => encode_u8((val as u8) << 2).into(),
        val if val <= MAXUINT14 => encode_u16((val as u16) << 2 | 0b01).into(),
        val if val <= MAXUINT30 => encode_u32((val as u32) << 2 | 0b10).into(),
        _ => panic!("invalid value"),
    }
}

pub fn encode_u8(val: u8) -> [u8; 1] {
    val.to_le_bytes()
}

pub fn encode_u16(val: u16) -> [u8; 2] {
    val.to_le_bytes()
}

pub fn encode_u32(val: u32) -> [u8; 4] {
    val.to_le_bytes()
}
