import { test, expect } from "vitest";
import { RSA } from "../src/RSA";
import { Factory } from "../src/Factory";
import { TKeyType } from "@veramo/core-types";
import { generateKeyPair, exportSPKI, importSPKI, exportPKCS8, importPKCS8, exportJWK, importJWK, KeyObject } from "jose";

const privkeypem = "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCw1pf3xAvEN3Zu\nUodO6UDZRydIQoI/jKNVDLZ81aGcyfbaD0tCA7oCxXbgq6AEnegY4GS6IwY78vA3\n5tVAmmHrwDRHBoFAKoU/fHe7Ojn4iCxWa1QXJ1SI1UYSgux/1LRoXUw/w4CxBpQx\ncqhPa/X5abOH6MNlrHUYWzPrC10FlZ2tZU5eZ0UKbGQR6d7mDt1LW/nOzDRmsFzV\nWIuVp6PTiHGtcMwaMULVOrB+iBnBfce28tMtnJi3Wg5TvGgxIR4ziKQDfDTl9Rqe\nlvf1uLJjFNs4Np0ufaFcw1jMdUE+ZOw0gegbA0MS8OefXr1XwcnOpMBRmseypgao\nKta7Wt9pAgMBAAECggEAARfCZqiSfgrts27VITq1yOH0rzCiB2yCEeN7OThEwGhL\nGzve9jB5tMytmGPXIFAtgAHa/X976WDt9Rp7FOQfWMqeSBYVNGVO336QatrIQu3s\ngDg3k9ENZ68RuMmQVpXk64QwFXDK2c01mzyfJ6Z+JaVuk5dvpbA0JQtjPb+bOo6Y\ngqMYEReUrgWY5ZrJEaU+Y3SxJjClkNkWk+NTNWWnNT5WjeY2bF/l5JnoTnMHq54B\nY12OxjysXmG4QIdaIvWEzx4VRw0C8rLP6gh4TNEFUY3nzxUSW6dy1vVttn0M902J\n8GCNUwKU+O2u8TlZTO/DwpA8iplSeuAFc7ZCA0ws1QKBgQDVd5/uOo29EPdttRer\n0ioU8/jAoDl4turzKqhoU2EhwRIAugNXDwrgpvmaOrvMwP3FeM2CtVrgEu6sk5dG\natwHDh+QmagsZywMztzL99sKcTLideoumQrZWztgmZwxLo6FtXgoAiR8lwwPeX98\nUZ1cGYvFAuIj78g1EwlGhHv/2wKBgQDUEp+jBl0m4eTlKxYKWdvpZoHQU/7585/Z\nkDONoIuoEDifk37zuWfz4UOsepP35EKxGYSsQPss6eT57egHqWlEQUp8QdLFC0NL\nOQuAgwkve4nhYQfjEDKgjvOiSR7wO8PqqHI8Q+mINzZ3ftBiWEYfHqkIr4TB+iyf\n0LtWV57zCwKBgEPmTxrJyTfwY6OjzKm8qeIMUH2E+YLqPAWo9fRpQSYpcX6FrHZO\ntJkMw6xJLl9Mq+vaJxSCdyt7GiwOrjmZ1+7ukR+/oHyvPJW+XwEKD8RciWD7PMgh\nqg/FMzfg5IvIUVE6jcO8Grr+mLl7Xg+/LhyTi5/Y8PGZXcd0DKk/jumtAoGAL83m\n6EPF+b7P7wywUjMBTHKL7p8Qid1t+gf0Zwd6k67cZLRF2MDBewsbSyTyd92fXvaG\nnqGjPPOYZvJG7Hs2vGkPVkUsMrigObOpMRXYmzh40zIhKgD7uI+gwcND0xlVx26j\nGYyhdtAjWfpfFNwbKmap6chO3776EihmIkdsEBMCgYB2mhmgz1vazblTYhnICMc6\naY8WBryQi0iSVZvZZzpgkT+X788gkOJCB4XrjHhkfLtwB5S91F1KFVJVW9jRu5Dd\nq85GSblqwhjWhFCMSXZpKGWpgdQdIsVmavHsAoXbnYpYnyY2g7/XVdPOv8zLyrEV\ngvVtT+jltRSpSg8Ai6tcjA==\n-----END PRIVATE KEY-----\n";
const pubkeypem = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNaX98QLxDd2blKHTulA\n2UcnSEKCP4yjVQy2fNWhnMn22g9LQgO6AsV24KugBJ3oGOBkuiMGO/LwN+bVQJph\n68A0RwaBQCqFP3x3uzo5+IgsVmtUFydUiNVGEoLsf9S0aF1MP8OAsQaUMXKoT2v1\n+Wmzh+jDZax1GFsz6wtdBZWdrWVOXmdFCmxkEene5g7dS1v5zsw0ZrBc1ViLlaej\n04hxrXDMGjFC1TqwfogZwX3HtvLTLZyYt1oOU7xoMSEeM4ikA3w05fUanpb39biy\nYxTbODadLn2hXMNYzHVBPmTsNIHoGwNDEvDnn169V8HJzqTAUZrHsqYGqCrWu1rf\naQIDAQAB\n-----END PUBLIC KEY-----";
const privkeyhex =
  "308204bc020100300d06092a864886f70d0101010500048204a6308204a20201000282010100b0d697f7c40bc437766e52874ee940d947274842823f8ca3550cb67cd5a19cc9f6da0f4b4203ba02c576e0aba0049de818e064ba23063bf2f037e6d5409a61ebc034470681402a853f7c77bb3a39f8882c566b5417275488d5461282ec7fd4b4685d4c3fc380b106943172a84f6bf5f969b387e8c365ac75185b33eb0b5d05959dad654e5e67450a6c6411e9dee60edd4b5bf9cecc3466b05cd5588b95a7a3d38871ad70cc1a3142d53ab07e8819c17dc7b6f2d32d9c98b75a0e53bc6831211e3388a4037c34e5f51a9e96f7f5b8b26314db38369d2e7da15cc358cc75413e64ec3481e81b034312f0e79f5ebd57c1c9cea4c0519ac7b2a606a82ad6bb5adf690203010001028201000117c266a8927e0aedb36ed5213ab5c8e1f4af30a2076c8211e37b393844c0684b1b3bdef63079b4ccad9863d720502d8001dafd7f7be960edf51a7b14e41f58ca9e48161534654edf7e906adac842edec80383793d10d67af11b8c9905695e4eb84301570cad9cd359b3c9f27a67e25a56e93976fa5b034250b633dbf9b3a8e9882a318111794ae0598e59ac911a53e6374b12630a590d91693e3533565a7353e568de6366c5fe5e499e84e7307ab9e01635d8ec63cac5e61b840875a22f584cf1e15470d02f2b2cfea08784cd105518de7cf15125ba772d6f56db67d0cf74d89f0608d530294f8edaef139594cefc3c2903c8a99527ae00573b642034c2cd502818100d5779fee3a8dbd10f76db517abd22a14f3f8c0a03978b6eaf32aa868536121c11200ba03570f0ae0a6f99a3abbccc0fdc578cd82b55ae012eeac9397466adc070e1f9099a82c672c0ccedccbf7db0a7132e275ea2e990ad95b3b60999c312e8e85b5782802247c970c0f797f7c519d5c198bc502e223efc835130946847bffdb02818100d4129fa3065d26e1e4e52b160a59dbe96681d053fef9f39fd990338da08ba810389f937ef3b967f3e143ac7a93f7e442b11984ac40fb2ce9e4f9ede807a96944414a7c41d2c50b434b390b8083092f7b89e16107e31032a08ef3a2491ef03bc3eaa8723c43e9883736777ed06258461f1ea908af84c1fa2c9fd0bb56579ef30b02818043e64f1ac9c937f063a3a3cca9bca9e20c507d84f982ea3c05a8f5f469412629717e85ac764eb4990cc3ac492e5f4cabebda271482772b7b1a2c0eae3999d7eeee911fbfa07caf3c95be5f010a0fc45c8960fb3cc821aa0fc53337e0e48bc851513a8dc3bc1abafe98b97b5e0fbf2e1c938b9fd8f0f1995dc7740ca93f8ee9ad0281802fcde6e843c5f9becfef0cb05233014c728bee9f1089dd6dfa07f467077a93aedc64b445d8c0c17b0b1b4b24f277dd9f5ef6869ea1a33cf39866f246ec7b36bc690f56452c32b8a039b3a93115d89b3878d332212a00fbb88fa0c1c343d31955c76ea3198ca176d02359fa5f14dc1b2a66a9e9c84edfbefa12286622476c1013028180769a19a0cf5bdacdb9536219c808c73a698f1606bc908b4892559bd9673a60913f97efcf2090e2420785eb8c78647cbb700794bdd45d4a1552555bd8d1bb90ddabce4649b96ac218d684508c4976692865a981d41d22c5666af1ec0285db9d8a589f263683bfd755d3cebfcccbcab11582f56d4fe8e5b514a94a0f008bab5c8c";
const pubkeyhex =
  "30820122300d06092a864886f70d01010105000382010f003082010a0282010100b0d697f7c40bc437766e52874ee940d947274842823f8ca3550cb67cd5a19cc9f6da0f4b4203ba02c576e0aba0049de818e064ba23063bf2f037e6d5409a61ebc034470681402a853f7c77bb3a39f8882c566b5417275488d5461282ec7fd4b4685d4c3fc380b106943172a84f6bf5f969b387e8c365ac75185b33eb0b5d05959dad654e5e67450a6c6411e9dee60edd4b5bf9cecc3466b05cd5588b95a7a3d38871ad70cc1a3142d53ab07e8819c17dc7b6f2d32d9c98b75a0e53bc6831211e3388a4037c34e5f51a9e96f7f5b8b26314db38369d2e7da15cc358cc75413e64ec3481e81b034312f0e79f5ebd57c1c9cea4c0519ac7b2a606a82ad6bb5adf690203010001";

test("Initialise key", async () => {
  const key = new RSA();
  await key.createPrivateKey();
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  const jwk = await exportJWK(await key.createCryptoKeyFromPrivateKey());
  expect(key.base64UrlToBytes(jwk.n).length).toBe(256);
  expect(key.base64UrlToBytes(jwk.e).length).toBe(3);
  expect(key.base64UrlToBytes(jwk.d).length).toBe(256);
  expect(key.base64UrlToBytes(jwk.p).length).toBe(128);
  expect(key.base64UrlToBytes(jwk.q).length).toBe(128);

  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);
  const jwk2 = await exportJWK(await key.createCryptoKeyFromPublicKey());
  expect(key.base64UrlToBytes(jwk2.n).length).toBe(256);
  expect(key.base64UrlToBytes(jwk.e).length).toBe(3);

  expect(key.algorithms()).toContain("RS256");
});

test("import RSA private key using PEM", async() => {
  const key = new RSA();
  await key.createPrivateKeyFromPEM(privkeypem);
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(1216);
  expect(key.exportPrivateKey()).toBe(privkeyhex);

  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import RSA public key using PEM", async() => {
  const key = new RSA();
  await key.createPublicKeyFromPEM(pubkeypem);
  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();

  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import private key", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(key.privateKeyBytes === null).toBeFalsy();
  expect(key.privateKeyBytes!.length).toBe(1216);
  expect(key.exportPrivateKey()).toBe(privkeyhex);

  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("import from DID", async () => {
  const key = await Factory.createFromDIDKey(
    "did:key:z2MGw4gk84USotaWf4AkJ83DcnrfgGaceF86KQXRYMfQ7xqnUGCh4Hdof93yJSQEDGruanJWynvWoKKXAogAmrZR8e86gGt4HNbiaZTc5zSYjdJb5DLFtS2MozrRo1cfju4MiTgrauzYFnJGenGWv8oPN1Tvznrsx2zz6oiAqxxEq3Y3G2RRvihFSywxJ4vveJfDnj5w7ob4mkmqikTbATwTcaqX858mjbHFd4evKJNsME1sG4nheGXHWhXovfmw7GMCibPHtYZ8vJWzFUjbZagmT8XDaJApTt6sxWidWX6DWwgjAETvLkwuhv3D8YDcCgYS13fULsdcy63mweSCvQUhvFqHhfTfsMUmhZYZR1mUqMeBmHtj5EJd47u8ay8x2iSZBUgwxfFsJK7RsSoaBS",
  );
  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(32);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("export to DID", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(await Factory.toDIDKey(key)).toBe(
    "did:key:z2MGw4gk84USotaWf4AkJ83DcnrfgGaceF86KQXRYMfQ7xqnUGCh4Hdof93yJSQEDGruanJWynvWoKKXAogAmrZR8e86gGt4HNbiaZTc5zSYjdJb5DLFtS2MozrRo1cfju4MiTgrauzYFnJGenGWv8oPN1Tvznrsx2zz6oiAqxxEq3Y3G2RRvihFSywxJ4vveJfDnj5w7ob4mkmqikTbATwTcaqX858mjbHFd4evKJNsME1sG4nheGXHWhXovfmw7GMCibPHtYZ8vJWzFUjbZagmT8XDaJApTt6sxWidWX6DWwgjAETvLkwuhv3D8YDcCgYS13fULsdcy63mweSCvQUhvFqHhfTfsMUmhZYZR1mUqMeBmHtj5EJd47u8ay8x2iSZBUgwxfFsJK7RsSoaBS",
  );
});

test("import from managed key", async () => {
  const key = new RSA();
  const mkey = {
    kid: pubkeyhex,
    type: "RSA" as TKeyType,
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
  const key = new RSA();
  const mkey = {
    kid: pubkeyhex,
    type: "RSA" as TKeyType,
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

test("signature RSA256", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS256", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature64 = await key.sign("RS256", message, "base64");
  expect(signature64).toBe(
    "9Ud+wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq+r6BEl5THBh8ze4/Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature16 = await key.sign("RS256", message, "base16");
  expect(signature16).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );

  const signaturehex = await key.sign("RS256", message, "hex");
  expect(signaturehex).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );
});

test("signature RSA512", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS512", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature64 = await key.sign("RS512", message, "base64");
  expect(signature64).toBe(
    "9Ud+wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq+r6BEl5THBh8ze4/Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );

  const signature16 = await key.sign("RS512", message, "base16");
  expect(signature16).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );

  const signaturehex = await key.sign("RS512", message, "hex");
  expect(signaturehex).toBe(
    "f5477ec2d63d1fa9dfb636273dd2aed272b8f32578d846568cc1f96a1abeafa0449794c7061f337b8fd3afcd7acc86102a870c80bb3c1f54eef2e6931cb6ea06",
  );
});

test("verify", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS256", message, "base64url");
  expect(signature).toBe(
    "9Ud-wtY9H6nftjYnPdKu0nK48yV42EZWjMH5ahq-r6BEl5THBh8ze4_Tr816zIYQKocMgLs8H1Tu8uaTHLbqBg",
  );
  const sigbytes = key.base64UrlToBytes(signature);
  expect(sigbytes.length).toBe(64);
  expect(await key.verify("RS256", sigbytes, message)).toBeTruthy();
});

test("create JWK", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(key.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();

  const jwk = await key.toJWK();
  expect(!!jwk).toBeTruthy();
  expect(jwk.kty).toBe("RSA");
  expect(jwk.n).toBe("XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk");
  expect(jwk.e).toBe("XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk");
});

test("import JWK", async () => {
  const jwk = {
    kty: "RSA",
    n: "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
    e: "XDGbjC1IAyAmc-0askvTQluRTUJIGWesTNk8z8feyzk",
  };
  const key = new RSA();
  await key.importFromJWK(jwk);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});
