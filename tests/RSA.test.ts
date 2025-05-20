import { test, expect } from "vitest";
import { RSA } from "../src/RSA";
import { Factory } from "../src/Factory";
import { CryptoKey } from "../src/CryptoKey";
import { TKeyType } from "@veramo/core-types";
import { fromString, toString } from "uint8arrays";
import { exportJWK } from "jose";

// to prevent signalling errors in the git repository, we're masking the test private key certificate
const privkeypem = toString(
  fromString(
    "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lHOXcwQkFRRUZBQVNDQktZd2dnU2lBZ0VBQW9JQkFRQ3cxcGYzeEF2RU4zWnUKVW9kTzZVRFpSeWRJUW9JL2pLTlZETFo4MWFHY3lmYmFEMHRDQTdvQ3hYYmdxNkFFbmVnWTRHUzZJd1k3OHZBMwo1dFZBbW1IcndEUkhCb0ZBS29VL2ZIZTdPam40aUN4V2ExUVhKMVNJMVVZU2d1eC8xTFJvWFV3L3c0Q3hCcFF4CmNxaFBhL1g1YWJPSDZNTmxySFVZV3pQckMxMEZsWjJ0WlU1ZVowVUtiR1FSNmQ3bUR0MUxXL25PekRSbXNGelYKV0l1VnA2UFRpSEd0Y013YU1VTFZPckIraUJuQmZjZTI4dE10bkppM1dnNVR2R2d4SVI0emlLUURmRFRsOVJxZQpsdmYxdUxKakZOczROcDB1ZmFGY3cxak1kVUUrWk93MGdlZ2JBME1TOE9lZlhyMVh3Y25PcE1CUm1zZXlwZ2FvCkt0YTdXdDlwQWdNQkFBRUNnZ0VBQVJmQ1pxaVNmZ3J0czI3VklUcTF5T0gwcnpDaUIyeUNFZU43T1RoRXdHaEwKR3p2ZTlqQjV0TXl0bUdQWElGQXRnQUhhL1g5NzZXRHQ5UnA3Rk9RZldNcWVTQllWTkdWTzMzNlFhdHJJUXUzcwpnRGczazlFTlo2OFJ1TW1RVnBYazY0UXdGWERLMmMwMW16eWZKNlorSmFWdWs1ZHZwYkEwSlF0alBiK2JPbzZZCmdxTVlFUmVVcmdXWTVackpFYVUrWTNTeEpqQ2xrTmtXaytOVE5XV25OVDVXamVZMmJGL2w1Sm5vVG5NSHE1NEIKWTEyT3hqeXNYbUc0UUlkYUl2V0V6eDRWUncwQzhyTFA2Z2g0VE5FRlVZM256eFVTVzZkeTF2VnR0bjBNOTAySgo4R0NOVXdLVStPMnU4VGxaVE8vRHdwQThpcGxTZXVBRmM3WkNBMHdzMVFLQmdRRFZkNS91T28yOUVQZHR0UmVyCjBpb1U4L2pBb0RsNHR1cnpLcWhvVTJFaHdSSUF1Z05YRHdyZ3B2bWFPcnZNd1AzRmVNMkN0VnJnRXU2c2s1ZEcKYXR3SERoK1FtYWdzWnl3TXp0ekw5OXNLY1RMaWRlb3VtUXJaV3p0Z21ad3hMbzZGdFhnb0FpUjhsd3dQZVg5OApVWjFjR1l2RkF1SWo3OGcxRXdsR2hIdi8yd0tCZ1FEVUVwK2pCbDBtNGVUbEt4WUtXZHZwWm9IUVUvNzU4NS9aCmtET05vSXVvRURpZmszN3p1V2Z6NFVPc2VwUDM1RUt4R1lTc1FQc3M2ZVQ1N2VnSHFXbEVRVXA4UWRMRkMwTkwKT1F1QWd3a3ZlNG5oWVFmakVES2dqdk9pU1I3d084UHFxSEk4USttSU56WjNmdEJpV0VZZkhxa0lyNFRCK2l5ZgowTHRXVjU3ekN3S0JnRVBtVHhySnlUZndZNk9qekttOHFlSU1VSDJFK1lMcVBBV285ZlJwUVNZcGNYNkZySFpPCnRKa013NnhKTGw5TXErdmFKeFNDZHl0N0dpd09yam1aMSs3dWtSKy9vSHl2UEpXK1h3RUtEOFJjaVdEN1BNZ2gKcWcvRk16Zmc1SXZJVVZFNmpjTzhHcnIrbUxsN1hnKy9MaHlUaTUvWThQR1pYY2QwREtrL2p1bXRBb0dBTDgzbQo2RVBGK2I3UDd3eXdVak1CVEhLTDdwOFFpZDF0K2dmMFp3ZDZrNjdjWkxSRjJNREJld3NiU3lUeWQ5MmZYdmFHCm5xR2pQUE9ZWnZKRzdIczJ2R2tQVmtVc01yaWdPYk9wTVJYWW16aDQwekloS2dEN3VJK2d3Y05EMHhsVngyNmoKR1l5aGR0QWpXZnBmRk53YkttYXA2Y2hPMzc3NkVpaG1Ja2RzRUJNQ2dZQjJtaG1nejF2YXpibFRZaG5JQ01jNgphWThXQnJ5UWkwaVNWWnZaWnpwZ2tUK1g3ODhna09KQ0I0WHJqSGhrZkx0d0I1UzkxRjFLRlZKVlc5alJ1NURkCnE4NUdTYmxxd2hqV2hGQ01TWFpwS0dXcGdkUWRJc1ZtYXZIc0FvWGJuWXBZbnlZMmc3L1hWZFBPdjh6THlyRVYKZ3ZWdFQramx0UlNwU2c4QWk2dGNqQT09Ci0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0K",
    "base64",
  ),
  "utf-8",
);
const pubkeypem =
  "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsNaX98QLxDd2blKHTulA\n2UcnSEKCP4yjVQy2fNWhnMn22g9LQgO6AsV24KugBJ3oGOBkuiMGO/LwN+bVQJph\n68A0RwaBQCqFP3x3uzo5+IgsVmtUFydUiNVGEoLsf9S0aF1MP8OAsQaUMXKoT2v1\n+Wmzh+jDZax1GFsz6wtdBZWdrWVOXmdFCmxkEene5g7dS1v5zsw0ZrBc1ViLlaej\n04hxrXDMGjFC1TqwfogZwX3HtvLTLZyYt1oOU7xoMSEeM4ikA3w05fUanpb39biy\nYxTbODadLn2hXMNYzHVBPmTsNIHoGwNDEvDnn169V8HJzqTAUZrHsqYGqCrWu1rf\naQIDAQAB\n-----END PUBLIC KEY-----";
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
  expect(CryptoKey.base64UrlToBytes(jwk.n!).length).toBe(256);
  expect(CryptoKey.base64UrlToBytes(jwk.e!).length).toBe(3);
  expect(CryptoKey.base64UrlToBytes(jwk.d!).length <= 256).toBeTruthy();
  expect(CryptoKey.base64UrlToBytes(jwk.d!).length > 253).toBeTruthy(); // in theory, smaller sizes could be possible
  expect(CryptoKey.base64UrlToBytes(jwk.p!).length).toBe(128);
  expect(CryptoKey.base64UrlToBytes(jwk.q!).length).toBe(128);

  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);
  const jwk2 = await exportJWK(await key.createCryptoKeyFromPublicKey());
  expect(CryptoKey.base64UrlToBytes(jwk2.n!).length).toBe(256);
  expect(CryptoKey.base64UrlToBytes(jwk2.e!).length).toBe(3);

  expect(key.algorithms()).toContain("RS256");
});

test("import RSA private key using PEM", async () => {
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

test("import RSA public key using PEM", async () => {
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
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
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
    "did:key:z2MGw4gk84USotaWf4AkJ83DcnrfgGaceF86KQXRYMfQ7xqnUFait8jjAP972BmAcheRzy3dsG8iW8GcYS1uZ4Ehc88x3wXbT5afwJuaSKBRkNsv8TNUUhttvsayZziwwR3NUyHFHeLw1nA4a94TCYrmjuT7Qb24tzDmdab9nhrWmDNc91KrnivF4SBQ8juviY8a1kCGcpKY7xUvEJDM72tB5C6rkV4MH9GQoDKNnApRDgWLmfLsK6EbytA1wq6BneP2QNHibSXchuiWc7cjLWkYJH8ATKbNgD326avgvqMh4gNZHJZBzcYLUhPaGZHc2EvxcPvcmrwj94UvaY8sSDzsNX9ZiWpdfn49PgaigCzBxPV3hkv7hUrc2EqWVZqNTViF2xQRk2KLQG13MoFeMv",
  );
  expect(key.hasPrivateKey()).toBeFalsy();
  expect(key.privateKeyBytes === null).toBeTruthy();
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("export to DID", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  expect(await Factory.toDIDKey(key)).toBe(
    "did:key:z2MGw4gk84USotaWf4AkJ83DcnrfgGaceF86KQXRYMfQ7xqnUFait8jjAP972BmAcheRzy3dsG8iW8GcYS1uZ4Ehc88x3wXbT5afwJuaSKBRkNsv8TNUUhttvsayZziwwR3NUyHFHeLw1nA4a94TCYrmjuT7Qb24tzDmdab9nhrWmDNc91KrnivF4SBQ8juviY8a1kCGcpKY7xUvEJDM72tB5C6rkV4MH9GQoDKNnApRDgWLmfLsK6EbytA1wq6BneP2QNHibSXchuiWc7cjLWkYJH8ATKbNgD326avgvqMh4gNZHJZBzcYLUhPaGZHc2EvxcPvcmrwj94UvaY8sSDzsNX9ZiWpdfn49PgaigCzBxPV3hkv7hUrc2EqWVZqNTViF2xQRk2KLQG13MoFeMv",
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
  expect(key.privateKeyBytes!.length).toBe(1216);
  expect(key.hasPublicKey()).toBeTruthy();
  expect(key.publicKeyBytes === null).toBeFalsy();
  expect(key.publicKeyBytes!.length).toBe(294);
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
  expect(key.publicKeyBytes!.length).toBe(294);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});

test("signature RS256", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS256", message, "base64url");
  expect(signature).toBe(
    "bYo4PCJqGiXc1SBC5Id7ouhkXgUUuSSzMbWQzsjqhgIe7NUeRWD1ErOuXP3aQf1hr9wvOu3ptY6J7E4n9lAKvahfpGEcRlFugWOXTMq1ZlnYdqNZeQLYmMn5U2e-n2Pefb74qiyZNTTNFDn9R5buHhn42s45zx7hqQBHISMVP-4_zsGfP2EeYr4dsu4vpHknUafjIgM87eXMiKU3SEUX6YdQVo5GgUnyCTwgFVhgZQkmr0_OGF1KbCCu4dldPv9kR97u_Id978EGNbQwUtKZkjLa0Y0XW8m822EOehLsuSW0RdiL5N13vKYzJKAUg77rbVom3sZe_XkDOGl1YkLpBg",
  );

  const signature64 = await key.sign("RS256", message, "base64");
  expect(signature64).toBe(
    "bYo4PCJqGiXc1SBC5Id7ouhkXgUUuSSzMbWQzsjqhgIe7NUeRWD1ErOuXP3aQf1hr9wvOu3ptY6J7E4n9lAKvahfpGEcRlFugWOXTMq1ZlnYdqNZeQLYmMn5U2e+n2Pefb74qiyZNTTNFDn9R5buHhn42s45zx7hqQBHISMVP+4/zsGfP2EeYr4dsu4vpHknUafjIgM87eXMiKU3SEUX6YdQVo5GgUnyCTwgFVhgZQkmr0/OGF1KbCCu4dldPv9kR97u/Id978EGNbQwUtKZkjLa0Y0XW8m822EOehLsuSW0RdiL5N13vKYzJKAUg77rbVom3sZe/XkDOGl1YkLpBg",
  );

  const signature16 = await key.sign("RS256", message, "base16");
  expect(signature16).toBe(
    "6d8a383c226a1a25dcd52042e4877ba2e8645e0514b924b331b590cec8ea86021eecd51e4560f512b3ae5cfdda41fd61afdc2f3aede9b58e89ec4e27f6500abda85fa4611c46516e8163974ccab56659d876a3597902d898c9f95367be9f63de7dbef8aa2c993534cd1439fd4796ee1e19f8dace39cf1ee1a900472123153fee3fcec19f3f611e62be1db2ee2fa4792751a7e322033cede5cc88a537484517e98750568e468149f2093c20155860650926af4fce185d4a6c20aee1d95d3eff6447deeefc877defc10635b43052d2999232dad18d175bc9bcdb610e7a12ecb925b445d88be4dd77bca63324a01483beeb6d5a26dec65efd79033869756242e906",
  );

  const signaturehex = await key.sign("RS256", message, "hex");
  expect(signaturehex).toBe(
    "6d8a383c226a1a25dcd52042e4877ba2e8645e0514b924b331b590cec8ea86021eecd51e4560f512b3ae5cfdda41fd61afdc2f3aede9b58e89ec4e27f6500abda85fa4611c46516e8163974ccab56659d876a3597902d898c9f95367be9f63de7dbef8aa2c993534cd1439fd4796ee1e19f8dace39cf1ee1a900472123153fee3fcec19f3f611e62be1db2ee2fa4792751a7e322033cede5cc88a537484517e98750568e468149f2093c20155860650926af4fce185d4a6c20aee1d95d3eff6447deeefc877defc10635b43052d2999232dad18d175bc9bcdb610e7a12ecb925b445d88be4dd77bca63324a01483beeb6d5a26dec65efd79033869756242e906",
  );
});

test("signature RSA512", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS512", message, "base64url");
  expect(signature).toBe(
    "rsAykGmPLCGKCpSRynsACTc3sUnFaiKA9UCCMX0uLd08FegWsmT_iwcE_LnAC_sur-PetuUJeN0QD40YWbKRm9gJ6gQ7-pl831L5CkGZ8oNAWjNSYzGm1hTr0v5NdXEVGp-XGdxsBsqda1o0pDguNODLk9jbE2TM74QWzaB5_TF64TJuP3LhoK5dgNbNIUkODJt6jcTKqm4HtaFPAQIS-ZOs1TEdv6T0z10UvuVkJcsphhJ_KmNdPqji_tygfzcmXv5Tw-GOWRfEp9RTk1bqY3mnpk1svxJFvd_mSNoS0KKf1-0WAis-_tIsxES3R3Izh73wzc3LqK4TL_hOdiUwUg",
  );

  const signature64 = await key.sign("RS512", message, "base64");
  expect(signature64).toBe(
    "rsAykGmPLCGKCpSRynsACTc3sUnFaiKA9UCCMX0uLd08FegWsmT/iwcE/LnAC/sur+PetuUJeN0QD40YWbKRm9gJ6gQ7+pl831L5CkGZ8oNAWjNSYzGm1hTr0v5NdXEVGp+XGdxsBsqda1o0pDguNODLk9jbE2TM74QWzaB5/TF64TJuP3LhoK5dgNbNIUkODJt6jcTKqm4HtaFPAQIS+ZOs1TEdv6T0z10UvuVkJcsphhJ/KmNdPqji/tygfzcmXv5Tw+GOWRfEp9RTk1bqY3mnpk1svxJFvd/mSNoS0KKf1+0WAis+/tIsxES3R3Izh73wzc3LqK4TL/hOdiUwUg",
  );

  const signature16 = await key.sign("RS512", message, "base16");
  expect(signature16).toBe(
    "aec03290698f2c218a0a9491ca7b00093737b149c56a2280f54082317d2e2ddd3c15e816b264ff8b0704fcb9c00bfb2eafe3deb6e50978dd100f8d1859b2919bd809ea043bfa997cdf52f90a4199f283405a33526331a6d614ebd2fe4d7571151a9f9719dc6c06ca9d6b5a34a4382e34e0cb93d8db1364ccef8416cda079fd317ae1326e3f72e1a0ae5d80d6cd21490e0c9b7a8dc4caaa6e07b5a14f010212f993acd5311dbfa4f4cf5d14bee56425cb2986127f2a635d3ea8e2fedca07f37265efe53c3e18e5917c4a7d4539356ea6379a7a64d6cbf1245bddfe648da12d0a29fd7ed16022b3efed22cc444b747723387bdf0cdcdcba8ae132ff84e76253052",
  );

  const signaturehex = await key.sign("RS512", message, "hex");
  expect(signaturehex).toBe(
    "aec03290698f2c218a0a9491ca7b00093737b149c56a2280f54082317d2e2ddd3c15e816b264ff8b0704fcb9c00bfb2eafe3deb6e50978dd100f8d1859b2919bd809ea043bfa997cdf52f90a4199f283405a33526331a6d614ebd2fe4d7571151a9f9719dc6c06ca9d6b5a34a4382e34e0cb93d8db1364ccef8416cda079fd317ae1326e3f72e1a0ae5d80d6cd21490e0c9b7a8dc4caaa6e07b5a14f010212f993acd5311dbfa4f4cf5d14bee56425cb2986127f2a635d3ea8e2fedca07f37265efe53c3e18e5917c4a7d4539356ea6379a7a64d6cbf1245bddfe648da12d0a29fd7ed16022b3efed22cc444b747723387bdf0cdcdcba8ae132ff84e76253052",
  );
});

test("verify RS256", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS256", message, "base64url");
  expect(signature).toBe(
    "bYo4PCJqGiXc1SBC5Id7ouhkXgUUuSSzMbWQzsjqhgIe7NUeRWD1ErOuXP3aQf1hr9wvOu3ptY6J7E4n9lAKvahfpGEcRlFugWOXTMq1ZlnYdqNZeQLYmMn5U2e-n2Pefb74qiyZNTTNFDn9R5buHhn42s45zx7hqQBHISMVP-4_zsGfP2EeYr4dsu4vpHknUafjIgM87eXMiKU3SEUX6YdQVo5GgUnyCTwgFVhgZQkmr0_OGF1KbCCu4dldPv9kR97u_Id978EGNbQwUtKZkjLa0Y0XW8m822EOehLsuSW0RdiL5N13vKYzJKAUg77rbVom3sZe_XkDOGl1YkLpBg",
  );
  const sigbytes = CryptoKey.base64UrlToBytes(signature);
  expect(sigbytes.length).toBe(256);
  expect(await key.verify("RS256", sigbytes, message)).toBeTruthy();
});

test("verify RS512", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();
  const message = Buffer.from("Message Data", "utf-8");
  const signature = await key.sign("RS512", message, "base64url");
  expect(signature).toBe(
    "rsAykGmPLCGKCpSRynsACTc3sUnFaiKA9UCCMX0uLd08FegWsmT_iwcE_LnAC_sur-PetuUJeN0QD40YWbKRm9gJ6gQ7-pl831L5CkGZ8oNAWjNSYzGm1hTr0v5NdXEVGp-XGdxsBsqda1o0pDguNODLk9jbE2TM74QWzaB5_TF64TJuP3LhoK5dgNbNIUkODJt6jcTKqm4HtaFPAQIS-ZOs1TEdv6T0z10UvuVkJcsphhJ_KmNdPqji_tygfzcmXv5Tw-GOWRfEp9RTk1bqY3mnpk1svxJFvd_mSNoS0KKf1-0WAis-_tIsxES3R3Izh73wzc3LqK4TL_hOdiUwUg",
  );
  const sigbytes = CryptoKey.base64UrlToBytes(signature);
  expect(sigbytes.length).toBe(256);
  expect(await key.verify("RS512", sigbytes, message)).toBeTruthy();
});

test("create JWK", async () => {
  const key = new RSA();
  await key.initialisePrivateKey(CryptoKey.hexToBytes(privkeyhex));
  expect(key.hasPrivateKey()).toBeTruthy();

  const jwk = await key.toJWK();
  expect(!!jwk).toBeTruthy();
  expect(jwk.kty).toBe("RSA");
  expect(jwk.n).toBe(
    "sNaX98QLxDd2blKHTulA2UcnSEKCP4yjVQy2fNWhnMn22g9LQgO6AsV24KugBJ3oGOBkuiMGO_LwN-bVQJph68A0RwaBQCqFP3x3uzo5-IgsVmtUFydUiNVGEoLsf9S0aF1MP8OAsQaUMXKoT2v1-Wmzh-jDZax1GFsz6wtdBZWdrWVOXmdFCmxkEene5g7dS1v5zsw0ZrBc1ViLlaej04hxrXDMGjFC1TqwfogZwX3HtvLTLZyYt1oOU7xoMSEeM4ikA3w05fUanpb39biyYxTbODadLn2hXMNYzHVBPmTsNIHoGwNDEvDnn169V8HJzqTAUZrHsqYGqCrWu1rfaQ",
  );
  expect(jwk.e).toBe("AQAB");
});

test("import JWK", async () => {
  const jwk = {
    kty: "RSA",
    n: "sNaX98QLxDd2blKHTulA2UcnSEKCP4yjVQy2fNWhnMn22g9LQgO6AsV24KugBJ3oGOBkuiMGO_LwN-bVQJph68A0RwaBQCqFP3x3uzo5-IgsVmtUFydUiNVGEoLsf9S0aF1MP8OAsQaUMXKoT2v1-Wmzh-jDZax1GFsz6wtdBZWdrWVOXmdFCmxkEene5g7dS1v5zsw0ZrBc1ViLlaej04hxrXDMGjFC1TqwfogZwX3HtvLTLZyYt1oOU7xoMSEeM4ikA3w05fUanpb39biyYxTbODadLn2hXMNYzHVBPmTsNIHoGwNDEvDnn169V8HJzqTAUZrHsqYGqCrWu1rfaQ",
    e: "AQAB",
  };
  const key = new RSA();
  await key.importFromJWK(jwk);
  expect(key.exportPublicKey()).toBe(pubkeyhex);
});
