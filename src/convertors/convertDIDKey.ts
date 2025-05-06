import { bases } from "multiformats/basics";
import { varint } from "multiformats";
import { Factory } from "../Factory";
import { CryptoKey } from "../CryptoKey";
import { convertFromDIDJWKBytes } from "./convertDIDJWK";

export function convertFromDIDKey(didUrl: string) {
  try {
    if (!didUrl.startsWith("did:key:")) {
      throw new Error("Unable to decode did:key " + didUrl);
    }

    const keycode = didUrl.split(":")[2].split("#")[0];
    // did:key is _always_ encoded as base58btc
    const bytestring = bases.base58btc.decode(keycode);
    const codec = varint.decode(bytestring);

    const pubkey = bytestring.slice(codec[1]);
    let key: CryptoKey | null = null;

    // https://github.com/multiformats/multicodec/blob/master/table.csv
    switch (codec[0]) {
      case 0xec: //        x25519-pub,                     key,            0xec,           draft,      Curve25519 public key
        key = Factory.createFromType("x25519");
        break;
      case 0xed: //        ed25519-pub,                    key,            0xed,           draft,      Ed25519 public key
        key = Factory.createFromType("Ed25519");
        break;
      case 0xe7: //        secp256k1-pub,                  key,            0xe7,           draft,      Secp256k1 public key (compressed)
        key = Factory.createFromType("Secp256k1");
        break;
      case 0x1200: //      p256-pub,                       key,            0x1200,         draft,      P-256 public Key (compressed)
        key = Factory.createFromType("Secp256r1");
        break;
      case 0xeb51: //      jwk_jcs-pub,                    key,            0xeb51,         draft,      JSON object containing only the required members of a JWK (RFC 7518 and RFC 7517) representing the public key. Serialisation based on JCS (RFC 8785)
        return convertFromDIDJWKBytes(pubkey);
      case 0xa0: //        aes-128,                        key,            0xa0,           draft,      128-bit AES symmetric key
      case 0xa1: //        aes-192,                        key,            0xa1,           draft,      192-bit AES symmetric key
      case 0xa2: //        aes-256,                        key,            0xa2,           draft,      256-bit AES symmetric key
      case 0xa3: //        chacha-128,                     key,            0xa3,           draft,      128-bit ChaCha symmetric key
      case 0xa4: //        chacha-256,                     key,            0xa4,           draft,      256-bit ChaCha symmetric key
      case 0xea: //        bls12_381-g1-pub,               key,            0xea,           draft,      BLS12-381 public key in the G1 field
      case 0xeb: //        bls12_381-g2-pub,               key,            0xeb,           draft,      BLS12-381 public key in the G2 field
      case 0xee: //        bls12_381-g1g2-pub,             key,            0xee,           draft,      BLS12-381 concatenated public keys in both the G1 and G2 fields
      case 0xef: //        sr25519-pub,                    key,            0xef,           draft,      Sr25519 public key
      case 0x1201: //      p384-pub,                       key,            0x1201,         draft,      P-384 public Key (compressed)
      case 0x1202: //      p521-pub,                       key,            0x1202,         draft,      P-521 public Key (compressed)
      case 0x1203: //      ed448-pub,                      key,            0x1203,         draft,      Ed448 public Key
      case 0x1204: //      x448-pub,                       key,            0x1204,         draft,      X448 public Key
      case 0x1205: //      rsa-pub,                        key,            0x1205,         draft,      RSA public key. DER-encoded ASN.1 type RSAPublicKey according to IETF RFC 8017 (PKCS #1)
      case 0x1206: //      sm2-pub,                        key,            0x1206,         draft,      SM2 public key (compressed)
      case 0x120b: //      mlkem-512-pub,                  key,            0x120b,         draft,      ML-KEM 512 public key; as specified by FIPS 203
      case 0x120c: //      mlkem-768-pub,                  key,            0x120c,         draft,      ML-KEM 768 public key; as specified by FIPS 203
      case 0x120d: //      mlkem-1024-pub,                 key,            0x120d,         draft,      ML-KEM 1024 public key; as specified by FIPS 203
      case 0x123a: //      multikey,                       multiformat,    0x123a,         draft,      Encryption key multiformat
      case 0x130c: //      bls12_381-g1-pub-share,         key,            0x130c,         draft,      BLS12-381 G1 public key share
      case 0x130d: //      bls12_381-g2-pub-share,         key,            0x130d,         draft,      BLS12-381 G2 public key share
      case 0x1a14: //      lamport-sha3-512-pub,           key,            0x1a14,         draft,      Lamport public key based on SHA3-512
      case 0x1a15: //      lamport-sha3-384-pub,           key,            0x1a15,         draft,      Lamport public key based on SHA3-384
      case 0x1a16: //      lamport-sha3-256-pub,           key,            0x1a16,         draft,      Lamport public key based on SHA3-256
      case 0xa000: //      chacha20-poly1305,              multikey,       0xa000,         draft,      ChaCha20_Poly1305 encryption scheme
        throw new Error("not implemented");
      default:
        throw new Error("not a proper public key");
    }

    if (key !== null) {
      // implementation is easy, but could be delegated to the key as importFromDID
      key.setPublicKey(key.bytesToHex(pubkey));
      return key;
    }
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
  } catch (e: any) {
    return null;
  }
  return null;
}

export function convertToMultibase(key: CryptoKey): string {
  let encoding = 0x0;
  let pubkey: Uint8Array;
  switch (key.keyType) {
    case "Ed25519":
      encoding = 0xed;
      pubkey = key.publicKey();
      break;
    case "X25519":
      encoding = 0xec;
      pubkey = key.publicKey();
      break;
    case "Secp256r1":
      encoding = 0x1200;
      pubkey = key.publicKey();
      break;
    case "Secp256k1":
      encoding = 0xe7;
      pubkey = key.publicKey();
      break;
    default:
      throw new Error(
        "Unable to convert key type " + key.keyType + " to a did:key",
      );
  }

  const prefixLength = varint.encodingLength(encoding);
  const multicodecEncoding = new Uint8Array(prefixLength + pubkey.length);
  varint.encodeTo(encoding, multicodecEncoding); // set prefix
  multicodecEncoding.set(pubkey, prefixLength); // add the original bytes
  return bases.base58btc.encode(multicodecEncoding);
}

export function convertToDIDKey(key: CryptoKey): string {
  return "did:key:" + convertToMultibase(key);
}
