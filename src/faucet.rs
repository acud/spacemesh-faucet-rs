use crate::grpc::Nonce;
use ed25519::pkcs8;
use ed25519::signature::{Keypair, SignatureEncoding, Signer};

const TEMPLATE: [u8; 24] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
];

pub struct Faucet<S: Nonce> {
    signing_key: ed25519_dalek::SigningKey,
    nonce: S,
}

impl<S: Nonce> Faucet<S> {
    pub fn new(signing_key: ed25519_dalek::SigningKey, nonce: S) -> Self {
        Faucet { signing_key, nonce }
    }
}

impl<S: Nonce> Faucet<S> {
    pub fn public_key(&self) -> pkcs8::PublicKeyBytes {
        let verifying_key = self.signing_key.verifying_key();
        pkcs8::PublicKeyBytes(verifying_key.to_bytes())
    }

    fn principal(&self) -> Vec<u8> {
        let pubkey = self.signing_key.verifying_key().to_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&TEMPLATE);
        hasher.update(&pubkey);
        let addr = hasher.finalize();
        let addr = addr.as_bytes();
        let addr: &[u8] = &addr[12..32];
        let mut data: Vec<u8> = vec![0, 0, 0, 0];
        data.extend_from_slice(addr);
        data
    }

    pub async fn sign(&self, msg: crate::DripTx) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let principal = self.principal();
        let dest = crate::hex::decode_hex(&msg.address)?;

        let nonce = self
            .nonce
            .next_nonce(crate::hex::encode_hex(principal.as_slice()))
            .await?;
        let nonce: u8 = nonce.try_into()?;
        let nonce = nonce << 2;
        let amount: u8 = msg.amount.try_into()?;
        let gasprice: u8 = 1 << 2;

        let mut data: Vec<u8> = Vec::new();
        data.push(0); //tx version 0

        data.extend(principal);
        data.push(16 << 2);
        data.push(nonce);
        data.push(gasprice);
        data.extend_from_slice(&dest);
        data.push(amount << 2);
        let bytes = data.as_slice();
        let prefix: [u8; 20] = [0; 20];
        let mut sign_data = Vec::<u8>::from(prefix);
        sign_data.extend_from_slice(bytes);
        let sig = self.signing_key.try_sign(&sign_data)?;
        data.extend_from_slice(&sig.to_bytes());
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use crate::hex::decode_hex;

    use ed25519_dalek::{Signer, SigningKey};

    use ed25519::pkcs8;

    fn ret_res(i: Option<u8>) -> Result<(), Box<dyn std::error::Error>> {
        let ii = i.ok_or("no val")?;
        Ok(())
    }

    #[test]
    fn test_err() {
        let val = Some(5u8);
        let val = None;
        match ret_res(val) {
            Ok(()) => println!("ok"),
            Err(e) => println!("err! {:?}", e),
        }
    }

    #[test]
    fn test_principal() {
        let key = decode_hex("1e71af5c8ee2b519b97cbcc39888372d61a5cd356c3fd7407371cff709209a2ab56b67eea72ae021a82ec3a9c8cd17f71a21067c3ac82b49f1d43cf78db3a780").unwrap();
        let arr: [u8; 64] = key.as_slice().try_into().unwrap();
        let signing_key = SigningKey::from_keypair_bytes(&arr).unwrap();
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&super::TEMPLATE);
        hasher.update(&pubkey);
        let addr = hasher.finalize();
        let addr = addr.as_bytes();
        let addr: &[u8] = &addr[12..32];
        let mut data: Vec<u8> = vec![0, 0, 0, 0];
        data.extend_from_slice(addr);

        let signing_key = SigningKey::from_keypair_bytes(&arr).unwrap();
        let faucet = super::Faucet::new(signing_key, crate::grpc::MockNonce::new());
        let principal = faucet.principal();
        assert_eq!(principal, data);
    }

    #[tokio::test]
    async fn test_sign() -> Result<(), ()> {
        let key = decode_hex("1e71af5c8ee2b519b97cbcc39888372d61a5cd356c3fd7407371cff709209a2ab56b67eea72ae021a82ec3a9c8cd17f71a21067c3ac82b49f1d43cf78db3a780").unwrap();
        let arr: [u8; 64] = key.as_slice().try_into().unwrap();
        let signing_key = SigningKey::from_keypair_bytes(&arr).unwrap();
        let verifying_key = signing_key.verifying_key();
        let mut mocknonce = crate::grpc::MockNonce::new();
        mocknonce.expect_next_nonce().times(1).returning(|_| Ok(0));
        let fct = super::Faucet::new(signing_key, mocknonce);
        let pubkey = verifying_key.to_bytes();
        let signing_key = SigningKey::from_keypair_bytes(&arr).unwrap();

        let mut hasher = blake3::Hasher::new();
        hasher.update(&super::TEMPLATE);
        hasher.update(&pubkey);
        let addr = hasher.finalize();
        let addr = addr.as_bytes();
        let addr: &[u8] = &addr[12..32];

        let nonce: u8 = 0;
        let amount: u8 = 1;
        let gasprice: u8 = 1;
        let dest: [u8; 24] = [
            0, 0, 0, 0, 49, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];

        let nonce = nonce << 2;
        let gasprice = gasprice << 2;

        let mut data: Vec<u8> = Vec::new();
        data.push(0);
        // push principal
        data.push(0);
        data.push(0);
        data.push(0);
        data.push(0);
        data.extend_from_slice(addr);
        data.push(16 << 2);
        data.push(nonce);
        data.push(gasprice);
        data.extend_from_slice(&dest);
        data.push(amount << 2);
        let bytes = data.as_slice();
        let prefix: [u8; 20] = [0; 20];
        let mut sign_data = Vec::<u8>::new();
        sign_data.extend_from_slice(&prefix);
        sign_data.extend_from_slice(&bytes);
        let res = signing_key.sign(sign_data.as_slice());
        data.extend_from_slice(&res.to_bytes());
        let amount: u64 = amount.try_into().unwrap();
        let faucet_msg = fct
            .sign(crate::DripTx {
                address: crate::hex::encode_hex(&dest),
                amount,
            })
            .await
            .unwrap();
        assert_eq!(faucet_msg, data);
        // the principle addr:
        // 24 bytes, with rightmost =1
        // first 32 bytes of the public key
        // both written into the blake3
        // take the 20 last bytes
        // then payload is nonce and gas price, both uint64
        // and the encoding is as follows:
        //
        /*func EncodeCompact64(e *Encoder, v uint64) (int, error) {
            if v <= maxUint6 {
                return encodeUint8(e, v<<2)
            } else if v <= maxUint14 {
                return encodeUint16(e, v<<2|0b01)
            } else if v <= maxUint30 {
                return encodeUint32(e, v<<2|0b10)
            }
            return encodeBigUint(e, uint64(v))
        }*/

        Ok(())
    }
}
