import { Factory } from "../Factory";
import { CryptoKey } from "../CryptoKey";

export async function convertFromJWK(jwk: JsonWebKey) {
  let key: CryptoKey | null = null;

  switch (jwk.kty) {
    case "OKP":
      switch (jwk.crv) {
        case "Ed25519":
          key = await Factory.createFromType("Ed25519");
          break;
        case "X25519":
          key = await Factory.createFromType("X25519");
          break;
      }
      break;
    case "EC":
      switch (jwk.crv) {
        case "P-256":
          key = await Factory.createFromType("Secp256r1");
          break;
        case "secp256k1":
          key = await Factory.createFromType("Secp256k1");
          break;
      }
      break;
    case "RSA":
      key = await Factory.createFromType("RSA");
  }
  if (!key) {
    throw new Error("JWK type " + jwk.kty + "/" + jwk.crv + " not supported");
  }
  await key.importFromJWK(jwk);
  return key;
}
