import { test, expect } from "vitest";
import { TKeyType } from "@veramo/core-types";
import { Ed25519 } from "../src/Ed25519";
import { Factory } from "../src/Factory";
import { CryptoKey } from "../src/CryptoKey";

const privkeyhex =
  "fbe04e71bce89f37e0970de16a97a80c4457250c6fe0b1e9297e6df778ae72a8";
const pubkeyhex =
  "5c319b8c2d4803202673ed1ab24bd3425b914d42481967ac4cd93ccfc7decb39";

test("Initialise key", async () => {
  const key = new Ed25519();
  await key.createPrivateKey();
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);

  expect(key.algorithms()).toContain("EdDSA");
});

test("import private key", async () => {
  const key = new Ed25519();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPrivateKey()).toBe(privkeyhex);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from DID", async () => {
  const key = await Factory.createFromDIDKey(
    "did:key:z6Mkkf9RiKeaAFaQzQGT2zfqqwCYYbPTNhQvyGXjKJ84kW88",
  );
  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("export to DID", async () => {
  const key = new Ed25519();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(await Factory.toDIDKey(key)).toBe(
    "did:key:z6Mkkf9RiKeaAFaQzQGT2zfqqwCYYbPTNhQvyGXjKJ84kW88",
  );
});

test("import from managed key", async () => {
  const key = new Ed25519();
  const mkey = {
    kid: pubkeyhex,
    type: "Ed25519" as TKeyType,
    kms: "default",
    publicKeyHex: pubkeyhex,
    privateKeyHex: privkeyhex,
  };
  await key.importFromManagedKey(mkey);

  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPrivateKey()).toBe(privkeyhex);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from managed public key", async () => {
  const key = new Ed25519();
  const mkey = {
    kid: pubkeyhex,
    type: "Ed25519" as TKeyType,
    kms: "default",
    publicKeyHex: pubkeyhex,
  };
  await key.importFromManagedKey(mkey);

  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("signature", async () => {
  const key = new Ed25519();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("EdDSA", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature64 = await key.sign("EdDSA", message, "base64");
  expect(signature64).toBe(
    "9Ud+wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq+r6BEl5THBh8ze4/Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature16 = await key.sign("EdDSA", message, "base16");
  expect(signature16).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );

  const signaturehex = await key.sign("EdDSA", message, "hex");
  expect(signaturehex).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );
});

test("verify", async () => {
  const key = new Ed25519();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("EdDSA", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );
  const sigbytes = CryptoKey.base64UrlToBytes(signature);
  expect(sigbytes.length).toBe(64);
  expect(await key.verify("EdDSA", sigbytes, message)).toBeTruthy();
});

test("create JWK", async () => {
  const key = new Ed25519();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();

  const jwk = await key.toJWK();
  expect(!!jwk).toBeTruthy();
  expect(jwk.kty).toBe("OKP");
  expect(jwk.crv).toBe("Ed25519");
  expect(jwk.x).toBe("XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk");
});

test("import JWK", async () => {
  const jwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
  };
  const key = new Ed25519();
  await key.importFromJWK(jwk);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});
