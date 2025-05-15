import { CryptoKey } from "./CryptoKey";
import { generateKeyPair, exportSPKI, importSPKI, exportPKCS8, importPKCS8, exportJWK, importJWK, KeyObject } from "jose";
import { toString } from "uint8arrays";
import * as crypto from 'node:crypto';

export class RSA extends CryptoKey {
  constructor() {
    super();
    this.keyType = "RSA";
  }

  async createPrivateKey() {
    await this.initialisePrivateKey();
  }

  async initialisePrivateKey(keyData?: Uint8Array)
  {
    const { privateKey, publicKey} = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
    await this.createPrivateKeyFromPEM(await exportPKCS8(privateKey));
    await this.createPublicKeyFromPEM(await exportSPKI(publicKey));
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
  }

  async createJoseKeyFromPrivateKey()
  {
    const pkHex = toString(this.privateKey(), 'base64');
    const pkHexBlocks = pkHex.match(/.{1,64}/g).join('\/');
    const pem = '-----BEGIN PRIVATE KEY-----\n' + pkHexBlocks + '\n-----END PRIVATE KEY-----';
    return await importPKCS8(pem, 'RS256');
  }

  async createJoseKeyFromPublicKey()
  {
    const pkHex = toString(this.publicKey(), 'base64');
    const pkHexBlocks = pkHex.match(/.{1,64}/g).join('\/');
    const pem = '-----BEGIN PUBLIC KEY-----\n' + pkHexBlocks + '\n-----END PUBLIC KEY-----';
    return await importSPKI(pem, 'RS256');
  }

  async toJWK(alg?:string): Promise<crypto.JsonWebKey> {
    const jkey = await this.createJoseKeyFromPublicKey();
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
    const key = await this.createJoseKeyFromPrivateKey();
    return new Uint8Array(await crypto.subtle.sign(algorithm, key, data));
  }

  async verify(algorithm: string, signature: Uint8Array, data: Uint8Array) {
    if (!this.algorithms().includes(algorithm)) {
      throw new Error(
        "Algorithm " + algorithm + " not supported on key type " + this.keyType,
      );
    }

    const key = await this.createJoseKeyFromPublicKey();
    const isValid = await crypto.subtle.verify(algorithm, key, signature, data);
    if (isValid) {
      return true;
    }
    return false;
  }
}
