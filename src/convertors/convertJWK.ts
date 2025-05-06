import { Factory } from "../Factory";
import { CryptoKey } from "../CryptoKey";

export function convertFromJWK(jwk: JsonWebKey) {
  let key: CryptoKey | null = null;

  switch (jwk.kty) {
    case "OKP":
      switch (jwk.crv) {
        case "Ed25519":
          key = Factory.createFromType("Ed25519");
          break;
        case "X25519":
          key = Factory.createFromType("X25519");
          break;
      }
      break;
    case "EC":
      switch (jwk.crv) {
        case "P-256":
          key = Factory.createFromType("Secp256r1");
          break;
        case "secp256k1":
          key = Factory.createFromType("Secp256k1");
          break;
      }
      break;
  }
  if (!key) {
    throw new Error("JWK type " + jwk.kty + "/" + jwk.crv + " not supported");
  }
  key.importFromJWK(jwk);
  return key;
}
