import { test, expect } from "vitest";
import { TKeyType } from "@veramo/core-types";
import { Secp256k1 } from "../src/Secp256k1";
import * as crypto from "node:crypto";

const privkeyhex = "e241c43ce7bbee7181be7788c46d9150b4dd1a4dd1f3ff66fe1b802b5e32ecb1";
const pubkeyhex = "034900ce66d2340ea0897c70d0a3fbb82c125ba163f9591ee090be097a11ad39f9";

test("Initialise key", () => {
  const key = new Secp256k1();
  key.createPrivateKey();
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);

  expect(key.algorithms()).toContain("ES256K");
});

test("import private key", () => {
  const key = new Secp256k1();
  key.initialisePrivateKey(
    key.hexToBytes(privkeyhex),
  );
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPrivateKey()).toBe(privkeyhex);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from DID", () => {
  const key = new Secp256k1();
  key.importFromDid(
    "did:key:zQ3shjZ5btPjB5qhUqJyH68XczxL11JqCTng4XBwhdy9nVYic",
  );
  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("export to DID", () => {
  const key = new Secp256k1();
  key.initialisePrivateKey(
    key.hexToBytes(privkeyhex),
  );
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.toDIDKey()).toBe(
    "zQ3shjZ5btPjB5qhUqJyH68XczxL11JqCTng4XBwhdy9nVYic",
  );
});

test("import from managed key", () => {
  const key = new Secp256k1();
  const mkey = {
    kid: pubkeyhex,
    type: "Secp256k1" as TKeyType,
    kms: "default",
    publicKeyHex: pubkeyhex,
    privateKeyHex: privkeyhex
  };
  key.importFromManagedKey(mkey);

  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPrivateKey()).toBe(
    privkeyhex
  );
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from managed public key", () => {
  const key = new Secp256k1();
  const mkey = {
    kid: pubkeyhex,
    type: "Ed25519" as TKeyType,
    kms: "default",
    publicKeyHex: pubkeyhex,
  };
  key.importFromManagedKey(mkey);

  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("signature", async () => {
  const key = new Secp256k1();
  key.initialisePrivateKey(
    key.hexToBytes(
      privkeyhex
    ),
  );
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("ES256K", message, "base64url");
  expect(signature).toBe(
    "Bu-qTAWcAU9vtkfEnhBohuSntoXPv90qVnq6w-8gbDQv9Coe1I8B448H9P-vxJXBe9TFi2CVgkrAjAJIczxhpg",
  );

  const signature64 = await key.sign("ES256K", message, "base64");
  expect(signature64).toBe(
    "Bu+qTAWcAU9vtkfEnhBohuSntoXPv90qVnq6w+8gbDQv9Coe1I8B448H9P+vxJXBe9TFi2CVgkrAjAJIczxhpg",
  );

  const signature16 = await key.sign("ES256K", message, "base16");
  expect(signature16).toBe(
    "06efaa4c059c014f6fb647c49e106886e4a7b685cfbfdd2a567abac3ef206c342ff42a1ed48f01e38f07f4ffafc495c17bd4c58b6095824ac08c0248733c61a6",
  );

  const signaturehex = await key.sign("ES256K", message, "hex");
  expect(signaturehex).toBe(
    "06efaa4c059c014f6fb647c49e106886e4a7b685cfbfdd2a567abac3ef206c342ff42a1ed48f01e38f07f4ffafc495c17bd4c58b6095824ac08c0248733c61a6",
  );
});

test("verify", async () => {
  const key = new Secp256k1();
  key.initialisePrivateKey(
    key.hexToBytes(
      privkeyhex
    ),
  );
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("ES256K", message, "base64url");
  expect(signature).toBe(
    "Bu-qTAWcAU9vtkfEnhBohuSntoXPv90qVnq6w-8gbDQv9Coe1I8B448H9P-vxJXBe9TFi2CVgkrAjAJIczxhpg",
  );
  expect(
    key.verify("ES256K", key.base64UrlToBytes(signature), message),
  ).toBeTruthy();

  const signature2 = await key.sign("ES256K-R", message, "hex");
  expect(signature2).toBe(
    "06efaa4c059c014f6fb647c49e106886e4a7b685cfbfdd2a567abac3ef206c342ff42a1ed48f01e38f07f4ffafc495c17bd4c58b6095824ac08c0248733c61a601",
  );
  expect(
    await key.verify("ES256K-R", key.hexToBytes(signature2), message),
  ).toBeTruthy();
});

test("toJWK", async () => {
  const key = new Secp256k1();
  key.initialisePrivateKey(
    key.hexToBytes(
      privkeyhex
    ),
  );
  expect(key.hasPrivateKey()).toBeTruthy();
  const jwk = key.toJWK();
  expect(jwk.crv).toBe("secp256k1");
  expect(jwk.x).toBe("SQDOZtI0DqCJfHDQo_u4LBJboWP5WR7gkL4JehGtOfk");
  expect(jwk.y).toBe("LHYCNBRST2GGkpcnODzo4bPimyMEIwe9pK1S5Ssjh7s");
});


test("import JWK", () => {
  const jwk = {
    kty: 'EC',
    crv: 'secp256k1',
    x: 'SQDOZtI0DqCJfHDQo_u4LBJboWP5WR7gkL4JehGtOfk',
    y: 'LHYCNBRST2GGkpcnODzo4bPimyMEIwe9pK1S5Ssjh7s'
  };
  const key = new Secp256k1();
  key.importFromJWK(jwk);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});