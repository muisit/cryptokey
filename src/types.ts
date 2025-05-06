// There are only 2 basic verification methods we support for output: JWK and Multikey
// All other methods appear to be subsets with a different naming
export enum VerificationMethods {
  "JsonWebKey", // defined in https://www.w3.org/TR/cid-1.0/
  "Multikey", // defined in https://www.w3.org/TR/cid-1.0/
}

export const contextFromKeyFormat: Record<string, string | object> = {
  JsonWebKey2020: ["https://w3id.org/security/suites/jws-2020/v1"], // deprecated
  Multikey: ["https://w3id.org/security/multikey/v1"],
  EcdsaSecp256k1VerificationKey2020: [
    "https://w3id.org/security/suites/secp256k1-2020/v1",
  ],
  EcdsaSecp256k1VerificationKey2019: [
    "https://w3id.org/security/suites/secp256k1-2019/v1",
  ], // deprecated
  Ed25519VerificationKey2020: [
    "https://w3id.org/security/suites/ed25519-2020/v1",
  ],
  Ed25519VerificationKey2018: [
    "https://w3id.org/security/suites/ed25519-2018/v1",
  ], // deprecated
  X25519KeyAgreementKey2020: [
    "https://w3id.org/security/suites/x25519-2020/v1",
  ],
  X25519KeyAgreementKey2019: [
    "https://w3id.org/security/suites/x25519-2019/v1",
  ], // deprecated
  EcdsaSecp256r1VerificationKey2019: [
    "https://w3id.org/security/suites/ecdsa-2019/v1",
  ],
};
