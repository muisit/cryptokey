import { CryptoKey } from "./CryptoKey";
import { createPrivateKey, createPublicKey } from 'crypto';
import { generateKeyPair, exportSPKI, importSPKI, exportPKCS8, importPKCS8, exportJWK, importJWK, KeyObject } from "jose";
import * as crypto from 'node:crypto';

export class RSA extends CryptoKey {
  constructor() {
    super();
    this.keyType = "RSA";
  }

  async createPrivateKey() {
    const { privateKey } = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
    await this.createPrivateKeyFromPEM(await exportPKCS8(privateKey));
  }

  async initialisePrivateKey(keyData?: Uint8Array)
  {
    if (!keyData) {
      await this.createPrivateKey();
    }
    else {
      this.privateKeyBytes = keyData;
      const privkey = await this.createCryptoKeyFromPrivateKey();
      const pubkey = createPublicKey(privkey);
      await this.createPublicKeyFromPEM(await exportSPKI(pubkey));
    }
  }

  async createPublicKeyFromPEM(pem:string)
  {
    const b64 = pem.replace(/-----BEGIN PUBLIC KEY-----/, '').replace(/-----END PUBLIC KEY-----/, '').replace(/\s+/g, '');
    this.publicKeyBytes = this.base64ToBytes(b64);
  }

  async createPrivateKeyFromPEM(pem:string)
  {
    const b64 = pem.replace(/-----BEGIN PRIVATE KEY-----/, '').replace(/-----END PRIVATE KEY-----/, '').replace(/\s+/g, '');
    this.privateKeyBytes = this.base64ToBytes(b64);

    // if we set the private key, determine the correct public key as well
    const privkey = createPrivateKey(pem);
    const pubkey = createPublicKey(privkey);
    await this.createPublicKeyFromPEM(await exportSPKI(pubkey));
  }

  // this returns a 'key-like' object, which is an abstraction of raw key bytes
  async createCryptoKeyFromPrivateKey()
  {
    const pkHex = this.bytesToBase64(this.privateKey(), true);
    const pkHexBlocks = pkHex.match(/.{1,64}/g)!.join('\n');
    const pem = '-----BEGIN PRIVATE KEY-----\n' + pkHexBlocks + '\n-----END PRIVATE KEY-----\n';
    return await importPKCS8(pem, 'RS256', {extractable:true});
  }

  async createCryptoKeyFromPublicKey()
  {
    const pkHex = this.bytesToBase64(this.publicKey(), true);
    const pkHexBlocks = pkHex.match(/.{1,64}/g)!.join('\n');
    const pem = '-----BEGIN PUBLIC KEY-----\n' + pkHexBlocks + '\n-----END PUBLIC KEY-----\n';
    return await importSPKI(pem, 'RS256', {extractable:true});
  }

  async toJWK(alg?:string): Promise<crypto.JsonWebKey> {
    const jkey = this.createCryptoKeyFromPublicKey();
    const retval = await exportJWK(jkey) as crypto.JsonWebKey;
    retval.alg = alg || 'RS256';
    retval.use = 'sig';
    retval.key_ops = ['verify'];
    return retval;
  }

  async importFromJWK(jwk: JsonWebKey) {
    if (jwk.kty == "RSA" && jwk.n && jwk.e) {
      const publicKey = await importJWK(jwk, jwk.alg || 'RS256');
      // is the below needed, or can we just use the bytes of the publicKey directly
      const pem = await exportPKCS8(publicKey as KeyObject);
      await this.createPublicKeyFromPEM(pem);
    }
  }

  algorithms() {
    return ["RS256", "RS512"];
  }

  async signBytes(algorithm: string, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }
    const key = await this.createCryptoKeyFromPrivateKey();
    return new Uint8Array(await crypto.subtle.sign(algorithm, key, data));
  }

  async verify(algorithm: string, signature: Uint8Array, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }

    const key = await this.createCryptoKeyFromPublicKey();
    const isValid = await crypto.subtle.verify(algorithm, key, signature, data);
    if (isValid) {
      return true;
    }
    return false;
  }
}
