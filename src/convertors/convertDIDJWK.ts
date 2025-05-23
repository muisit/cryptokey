import { fromString, toString } from "uint8arrays";
import { CryptoKey } from "../CryptoKey";
import { Factory } from "../Factory";

export async function convertFromDIDJWK(didUrl: string): Promise<CryptoKey> {
  if (!didUrl.startsWith("did:jwk:")) {
    throw new Error("Invalid did:jwk");
  }
  const encoded = didUrl.slice(8);
  return await convertFromDIDJWKBytes(fromString(encoded, "base64url"));
}

export async function convertFromDIDJWKBytes(
  bytes: Uint8Array,
): Promise<CryptoKey> {
  const jsonString = toString(bytes, "utf-8");
  const jwk = JSON.parse(jsonString);
  if (jwk && Object.keys(jwk) && jwk.kty && jwk.crv) {
    return await Factory.createFromJWK(jwk);
  }
  throw new Error("Unable to decode jwk");
}

// https://github.com/quartzjer/did-jwk/blob/main/spec.md
export async function convertToDIDJWK(key: CryptoKey): Promise<string> {
  const jwk = await key.toJWK();
  // remove some elements we do not need in the output
  if (jwk.kid) delete jwk.kid; // the did is its own id
  if (jwk.key_ops) delete jwk.key_ops;
  if (jwk.d) delete jwk.d; // did:jwk is never ever a private key
  return (
    "did:jwk:" + toString(fromString(JSON.stringify(jwk), "utf-8"), "base64url")
  );
}
