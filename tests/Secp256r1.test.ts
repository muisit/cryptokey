import { test, expect } from "vitest";
import { TKeyType } from "@veramo/core-types";
import { Secp256r1 } from "../src/Secp256r1";
import * as crypto from "node:crypto";
import { Factory } from "../src/Factory";
import { CryptoKey } from "../src/CryptoKey";
import { ec } from 'elliptic';
import { toString, fromString } from 'uint8arrays';

const privkeyhex =
  "44d2575ca39d5b875b17f3ae372183acd1da561dbbfde6591facbca98b83fb11";
const pubkeyhex =
  "03c6e2792c9be06396a078151bc89e6f553412cab000c7ec71c5b992938356d980";

test("Initialise key", async () => {
  const key = new Secp256r1();
  await key.createPrivateKey();
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);

  expect(key.algorithms()).toContain("ES256");
});

test("import private key", async () => {
  const key = new Secp256r1();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(32);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPrivateKey()).toBe(privkeyhex);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from DID", async () => {
  const key = await Factory.createFromDIDKey(
    "did:key:zDnaew3eSC3JmvrFcgwgoGULgcm3iQR9han5k2d4P87vsDkdm",
  );
  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("export to DID", async () => {
  const key = new Secp256r1();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(await Factory.toDIDKey(key)).toBe(
    "did:key:zDnaew3eSC3JmvrFcgwgoGULgcm3iQR9han5k2d4P87vsDkdm",
  );
});

test("import from managed key", async () => {
  const key = new Secp256r1();
  const mkey = {
    kid: pubkeyhex,
    type: "Secp256r1" as TKeyType,
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
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPrivateKey()).toBe(privkeyhex);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from managed public key", async () => {
  const key = new Secp256r1();
  const mkey = {
    kid: pubkeyhex,
    type: "Secp256r1" as TKeyType,
    kms: "default",
    publicKeyHex: pubkeyhex,
  };
  await key.importFromManagedKey(mkey);

  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(33);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("signature", async () => {
  const key = new Secp256r1();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("ES256", message, "base64url");
  expect(signature).toBe(
    "RRFwdKcuhC3-q2SG2laZKzB0VnSvyKQxqQAv3EDvPY0IhLrSO-33IVozCMKFT8toGQsL3NI-7d8t7Pp_xdbrqQ",
  );

  const signature64 = await key.sign("ES256", message, "base64");
  expect(signature64).toBe(
    "RRFwdKcuhC3+q2SG2laZKzB0VnSvyKQxqQAv3EDvPY0IhLrSO+33IVozCMKFT8toGQsL3NI+7d8t7Pp/xdbrqQ",
  );

  const signature16 = await key.sign("ES256", message, "base16");
  expect(signature16).toBe(
    "45117074a72e842dfeab6486da56992b30745674afc8a431a9002fdc40ef3d8d0884bad23bedf7215a3308c2854fcb68190b0bdcd23eeddf2decfa7fc5d6eba9",
  );

  const signaturehex = await key.sign("ES256", message, "hex");
  expect(signaturehex).toBe(
    "45117074a72e842dfeab6486da56992b30745674afc8a431a9002fdc40ef3d8d0884bad23bedf7215a3308c2854fcb68190b0bdcd23eeddf2decfa7fc5d6eba9",
  );
});

test("verify", async () => {
  const key = new Secp256r1();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("ES256", message, "base64url");
  expect(
    await key.verify("ES256", CryptoKey.base64UrlToBytes(signature), message),
  ).toBeTruthy();
});

test("toJWK", async () => {
  const key = new Secp256r1();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const jwk = await key.toJWK();
  expect(jwk.kty).toBe("EC");
  expect(jwk.crv).toBe("P-256");
  expect(jwk.x).toBe("xuJ5LJvgY5ageBUbyJ5vVTQSyrAAx-xxxbmSk4NW2YA");
  expect(jwk.y).toBe("ZHujYr-HhNmVrtdf4icztCM2eMJ6XCq42MwwuhkD6dE");
  const ckey = await crypto.subtle.importKey(
    "jwk",
    jwk as crypto.JsonWebKey,
    {
      name: "ECDSA",
      namedCurve: "P-256",
    },
    false,
    jwk.key_ops as KeyUsage[],
  );
  expect(ckey).toBeDefined();
  expect(ckey.type).toBe("public");
  expect(ckey.usages).toStrictEqual(jwk.key_ops);
});

test("import JWK", async () => {
  const jwk = {
    kty: "EC",
    crv: "P-256",
    x: "xuJ5LJvgY5ageBUbyJ5vVTQSyrAAx-xxxbmSk4NW2YA",
    y: "ZHujYr-HhNmVrtdf4icztCM2eMJ6XCq42MwwuhkD6dE",
  };
  const key = new Secp256r1();
  await key.importFromJWK(jwk);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("case: private key conversion issues", async () => {
  const keys = [
    "780d0b34863626ead5cf6a4c63229bd83b0491c739ca370e5656ebcd30f0b719",
    "314230f7386428ef4ec3f060ad45e8801055c72e9f7d1f0dd6fca2ef7780b8e5",
    "7311657d96b840db111792d1fd0984f34fd472e05169c6cc3d044327ec5d9a87",
    "b3ebe20b402425da6bf8d5adc2523aa0824a53ad95cbd375167257c034dacd79",
    "3fcb7cb4bb434755df930dbb4a9165d566c72c005feb0817235c3183a72844f7",
    "48e92cb0a2f213491af2fb269b470ce36e5db27aaf956827d84518c14938cf0d",
    "c9e01f9295b8336854bb2027500f5702f55f4fcfd8040894e36ab606b8c583f1",
    "a8fd4f9d4c432a40799e6642642951191c78b1baf422a668dd5fa79c50d0d244",
    "ce988a72edaf94bc24589fa4ac4a9271a7edafdd2033dd8d386ef7575039511c"
  ];

  for (const pkey of keys) {
    const key = new Secp256r1();
    await key.initialisePrivateKey(CryptoKey.hexToBytes(pkey));
    expect(key.hasPrivateKey()).toBeTruthy();
    expect(key.privateKeyBytes === null).toBeFalsy();
    expect(key.privateKeyBytes!.length).toBe(32);
    expect(key.hasPublicKey()).toBeTruthy();
    expect(key.publicKeyBytes === null).toBeFalsy();
    expect(key.publicKeyBytes!.length).toBe(33);
    expect(key.exportPrivateKey()).toBe(pkey);

    const curve = new ec('p256');
    const eckey = curve.keyFromPrivate(pkey, 16);
    const encoded = curve.sign(fromString(pkey, 'utf-8'), pkey, 16);
    const verified = eckey.verify(fromString(pkey, 'utf-8'), encoded, eckey.getPublic());
    expect(verified).toBeTruthy();
  }
});

test("case: jwk conversion issues", async () => {
  const jwk = {"alg":"ES256","use":"sig","kty":"EC","crv":"P-256","x":"2Aid8BULnxp60VvY6juu1fNrEbM02qucl6k3P3oA0w","y":"5u6XAjfCjPfiw2Tj_pHj7BPgZZ4coUZLtjSfaMviKms","kid":"LKZBjBfSVDPNl9hJWvtsxb8IBi9SMXf2deBMDqaw7xw"};
  await expect(() => Factory.createFromJWK(jwk)).rejects.toThrow("bad point: equation left != right");
});