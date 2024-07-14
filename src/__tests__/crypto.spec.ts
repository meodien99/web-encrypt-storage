import { decrypt, deriveKey, encrypt, generateCryptoKey } from "../scripts/crypto";
import { decode, generateNonce, generateRandomValues, generateSalt, getCryptoObject } from "../scripts/crypto/crypto.utils";

describe('Crypto Utils Tests', () => {
  beforeEach(() => {
    // setCryptoObjectForTesting(global.crypto);
  });

  describe('Get Crypto Object', () => {
    let orgCrypto: Crypto = global.crypto;
    it('should always get crypto object', () => {
      const o = getCryptoObject();

      expect(o).toEqual(orgCrypto);
    });
  });

  describe('Generate Base Key', () => {
    it('should accept JWK', async () => {
      const jwkEcKey = {
        "crv": "P-384",
        "d": "wouCtU7Nw4E8_7n5C1-xBjB4xqSb_liZhYMsy8MGgxUny6Q8NCoH9xSiviwLFfK_",
        "ext": true,
        "key_ops": ["sign"],
        "kty": "EC",
        "x": "SzrRXmyI8VWFJg1dPUNbFcc9jZvjZEfH7ulKI1UkXAltd7RGWrcfFxqyGPcwu6AQ",
        "y": "hHUag3OvDzEr0uUQND4PXHQTXP5IDGdYhJhL-WLKjnGjQAw0rNGy5V29-aV-yseW"
      };

      const cryptoKey = await generateCryptoKey({
        raw: jwkEcKey, algorithm: {
          name: 'ECDSA',
          namedCurve: 'P-384'
        }, keyUsages: ['sign']
      });

      expect(cryptoKey.algorithm).toEqual({
        name: 'ECDSA',
        //@ts-ignore
        namedCurve: 'P-384'
      });
    });

    it('should not be extractable', async () => {
      const cryptoKey = await generateCryptoKey({ raw: 'any key' });
      expect(cryptoKey.extractable).toBeFalse();
    });

    it('should accept typed array as key data', async () => {
      const cryptoKey = await generateCryptoKey({ raw: new Uint8Array(8) });
      expect(cryptoKey.extractable).toBeFalse();
    });

    it('should use PBKDF2 algorithm by default', async () => {
      const cryptoKey = await generateCryptoKey({ raw: 'any key' });
      expect(cryptoKey.algorithm).toEqual({ name: 'PBKDF2' });
    });

    it('should be used just for derive a new key by default', async () => {
      const cryptoKey = await generateCryptoKey({ raw: 'any key' });
      expect(cryptoKey.usages).toEqual(['deriveKey']);
    });

    it('should work with other algorithms and usages', async () => {
      const key = await generateCryptoKey({
        raw: generateRandomValues(16),
        algorithm: 'AES-GCM',
        keyUsages: ['encrypt', 'decrypt'],
        format: 'raw'
      });

      //@ts-ignore
      expect(key.algorithm).toEqual({ name: 'AES-GCM', length: 128 });
    });
  });

  describe('Derive key tests', () => {
    it('should be able to do derive a key from base key', async () => {
      const key = await generateCryptoKey({ raw: 'any key' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });

      expect(cryptoKey).toBeDefined();
    });

    it('should be able to derive a key from the custom iterations', async () => {
      const key = await generateCryptoKey({ raw: 'any key' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt(), iterationsOrAlgorithmParam: 150 });

      expect(cryptoKey).toBeDefined();
    });

    it('should not be extractable', async () => {
      const key = await generateCryptoKey({ raw: 'any key' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });

      expect(cryptoKey.extractable).toBeFalse();
    });

    it('should be able to set the key usages', async () => {
      const key = await generateCryptoKey({ raw: 'any key' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt(), keyUsages: ['encrypt'] });

      expect(cryptoKey.usages).toEqual(['encrypt']);
    });

    it('should use AES-GCM with length 256 by default', async () => {
      const key = await generateCryptoKey({ raw: 'any key' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });

      //@ts-ignore
      expect(cryptoKey.algorithm).toEqual({ name: 'AES-GCM', length: 256 });
    });

    it('should be able to use other algorithms', async () => {
      const key = await generateCryptoKey({ raw: 'any key' });
      const cryptoKey = await deriveKey({
        key, saltOrDeriveAlgorithm: {
          name: 'PBKDF2',
          salt: generateSalt(),
          iterations: 100,
          hash: 'SHA-1'
        }
      });

      expect(cryptoKey).toBeDefined();
    });

    it('should be able to use other target encrypt algorithms', async () => {
      const key = await generateCryptoKey({ raw: 'any key' });
      const cryptoKey = await deriveKey({
        key,
        saltOrDeriveAlgorithm: generateSalt(),
        iterationsOrAlgorithmParam: {
          name: 'AES-CBC',
          length: 256
        }
      });

      expect(cryptoKey.algorithm).toEqual({
        name: 'AES-CBC',
        //@ts-ignore
        length: 256
      });
    });
  });

  describe('Encryption data', () => {
    it('should return the encrypted value and nonce when using strings', async () => {
      const key = await generateCryptoKey({ raw: 'raw key' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });
      const [cryptedValue, nonce] = await encrypt({ data: 'raw key', key: cryptoKey });

      expect(cryptedValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toBeInstanceOf(Uint8Array);
    });

    it('should return the encrypted value and nonce when using typed array', async () => {
      const orgData = new Uint8Array(8);
      const key = await generateCryptoKey({ raw: 'raw key' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });
      const [cryptedValue, nonce] = await encrypt({ data: orgData, key: cryptoKey });

      expect(cryptedValue).not.toEqual(orgData);
      expect(cryptedValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toBeInstanceOf(Uint8Array);
    });

    it('should return the encrypted value and nonce when using a custom AES algorithm', async () => {
      const key = await generateCryptoKey({ raw: 'raw key' });
      const cryptoKey = await deriveKey({
        key,
        saltOrDeriveAlgorithm: generateSalt(),
        iterationsOrAlgorithmParam: {
          name: 'AES-CBC',
          length: 256
        }
      });
      const customAlgo = { name: 'AES-CBC', iv: generateNonce() };
      const [cryptedValue, nonce] = await encrypt({ data: 'raw key', key: cryptoKey, algorithm: customAlgo });

      expect(cryptedValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toEqual(customAlgo.iv);
    });

    it('should return the encrypted value and null nonce when using a custom AES algorithm without iv', async () => {
      const cryptoKey = await global.crypto.subtle.generateKey({
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256'
      }, true, ['encrypt', 'decrypt']);

      const customAlgo = { name: 'RSA-OAEP' };
      const [cryptedValue, nonce] = await encrypt({ data: 'raw key', key: cryptoKey.publicKey, algorithm: customAlgo });

      expect(cryptedValue).toBeInstanceOf(ArrayBuffer);
      expect(nonce).toBeNull();
    });
  });

  describe('Decryption data', () => {
    it('should decrypt the given value using the default nonce', async () => {
      const orgData = 'thisistextwith17l';
      const key = await generateCryptoKey({ raw: 'raw data 2' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });
      const [crypted, nonce] = await encrypt({ data: orgData, key: cryptoKey });

      if (nonce) {
        const decrypted = await decrypt({ data: crypted, key: cryptoKey, nonceOrAlgorithm: nonce });
        expect(orgData).toEqual(decode(decrypted));
      }
    });

    it('should decrypt the given typed Array using the default nonce', async () => {
      const orgData = new Uint8Array([1, 2, 33, 44, 556]);
      const key = await generateCryptoKey({ raw: 'any raw' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });
      const [crypted, nonce] = await encrypt({ data: orgData, key: cryptoKey });

      if (nonce) {
        const decrypted = await decrypt({ data: crypted, key: cryptoKey, nonceOrAlgorithm: nonce });
        expect(orgData).toEqual(new Uint8Array(decrypted));
      }
    });

    it('should decrypt the given value with custom algo', async () => {
      const orgData = 'raw data';
      const key = await generateCryptoKey({ raw: 'any raw' });
      const cryptoKey = await deriveKey({
        key,
        saltOrDeriveAlgorithm: generateSalt(),
        iterationsOrAlgorithmParam: {
          name: 'AES-CBC',
          length: 256
        }
      });

      const customAlgo = { name: 'AES-CBC', iv: generateNonce() };

      const [crypted] = await encrypt({ data: orgData, key: cryptoKey, algorithm: customAlgo });

      const decrypted = await decrypt({ data: crypted, key: cryptoKey, nonceOrAlgorithm: customAlgo });
      expect(orgData).toEqual(decode(decrypted));
    });

    it('should not decrypt the given value using incorrect nonce', async () => {
      const orgData = 'thisistextwith17l';
      const key = await generateCryptoKey({ raw: 'raw data' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });
      const [crypted, nonce] = await encrypt({ data: orgData, key: cryptoKey });


      if(nonce) {
        const newCryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });
        const error = await decrypt({ data: crypted, key: newCryptoKey, nonceOrAlgorithm: nonce }).catch(e => e);

        expect(error.name).toEqual('OperationError');
      }
    });

    it('should not decrypt the given value using incorrect crypto key', async () => {
      const orgData = 'thisistextwith17l';
      const key = await generateCryptoKey({ raw: 'raw data' });
      const cryptoKey = await deriveKey({ key, saltOrDeriveAlgorithm: generateSalt() });
      const [crypted,] = await encrypt({ data: orgData, key: cryptoKey });

      const decryptOperator = decrypt({ data: crypted, key: cryptoKey, nonceOrAlgorithm: generateNonce() });
      await expectAsync(decryptOperator).toBeRejectedWithError();
    });
  });
});
