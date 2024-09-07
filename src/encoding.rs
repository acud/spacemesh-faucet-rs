use std::{fmt::Write, num::ParseIntError};

const MAXUINT6: usize = (1 << 6) - 1;
const MAXUINT8: usize = (1 << 8) - 1;
const MAXUINT14: usize = (1 << 14) - 1;
const MAXUINT16: usize = (1 << 16) - 1;
const MAXUINT30: usize = (1 << 30) - 1;

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

#[cfg(test)]
mod tests {

    #[test]
    fn test() {
        let tc: Vec<(usize, Vec<u8>)> = vec![
            // u8 cases
            (0, vec![0b0000_0000]),
            (1, vec![0b0000_0100]),
            (super::MAXUINT6, vec![0b1111_1100]),
            (super::MAXUINT8, vec![0b1111_1101, 0b0000_0011]),
            //u16 cases
            (0, vec![0b0000_0000]),
            (1, vec![0b0000_0100]),
            (super::MAXUINT6, vec![0b1111_1100]),
            (super::MAXUINT8, vec![0b1111_1101, 0b0000_0011]),
            (super::MAXUINT14, vec![0b1111_1101, 0b1111_1111]),
            (
                (super::MAXUINT14 + 1),
                vec![0b0000_0010, 0b0000_0000, 0b0000_0001, 0b0000_0000],
            ),
            (
                super::MAXUINT16,
                vec![0b1111_1110, 0b1111_1111, 0b0000_0011, 0b0000_0000],
            ),
            // u32 cases
            (0, vec![0b0000_0000]),
            (1, vec![0b0000_0100]),
            (super::MAXUINT6, vec![0b1111_1100]),
            (super::MAXUINT8, vec![0b1111_1101, 0b0000_0011]),
            (super::MAXUINT14, vec![0b1111_1101, 0b1111_1111]),
            (
                super::MAXUINT14 + 1,
                vec![0b0000_0010, 0b0000_0000, 0b0000_0001, 0b0000_0000],
            ),
            (
                super::MAXUINT16,
                vec![0b1111_1110, 0b1111_1111, 0b0000_0011, 0b0000_0000],
            ),
            (
                super::MAXUINT30,
                vec![0b1111_1110, 0b1111_1111, 0b1111_1111, 0b1111_1111],
            ),
            // these won't encode since the scale varint encoding is missing
            // in the implementation
            //(
            //super::MAXUINT30 + 1,
            //vec![
            //0b0000_0011,
            //0b0000_0000,
            //0b0000_0000,
            //0b0000_0000,
            //0b0100_0000,
            //],
            //),
            //(
            //u32::MAX as usize,
            //vec![
            //0b0000_0011,
            //0b1111_1111,
            //0b1111_1111,
            //0b1111_1111,
            //0b1111_1111,
            //],
            //),
        ];
        for (i, tc) in tc.iter().enumerate() {
            let ret = super::encode_usize(tc.0);
            println!("checking case {}", i);
            assert_eq!(ret, tc.1);
        }
    }
}
