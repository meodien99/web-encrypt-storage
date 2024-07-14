let C: Crypto = window.crypto;

// setup 3rd party cryptoObject
export function setCryptoObjectForTesting(c: Crypto) {
  C = c;
}

export function getCryptoObject(): Crypto {
  return C || window.crypto;
}

/**
 * Type Guard to Typed Array.
 *
 * @returns true if the given data is a Typed Array.
 */
export function isTypedArray(data: unknown): data is BufferSource {
  return ArrayBuffer.isView(data) || data instanceof ArrayBuffer;
}

/**
 * Encode a string or BufferSource value to a Typed Array as `Uint8Array`.
 *
 * @returns The transformed given value as a Typed Array.
 */
export function encode(data: string | BufferSource): BufferSource {
  return isTypedArray(data) ? data : new TextEncoder().encode(data);
}

/**
 * Decode a BufferSource value to a string.
 *
 * @returns The transformed given value as a string.
 */
export function decode(data: string | BufferSource): string {
  return typeof data === 'string' ? data : new TextDecoder('utf-8').decode(data);
}

/**
 * Generate random value
 *
 * @param byteSize The byte size of generated random value
 * @returns The random value
 */
export function generateRandomValues(byteSize = 8): Uint8Array {
  return getCryptoObject().getRandomValues(new Uint8Array(byteSize))
}

/**
 * Generates random value to be used as nonce with encryption algorithms,
 * a nonce is an arbitrary number that can be used just once in a cryptographic communication,
 * should at least 16 bytes to allow for 2^128 possible variations.
 *
 * @param byteSize The byte size of the generated random value.
 * @returns The random value
 */
export function generateNonce(byteSize = 16): Uint8Array {
  return generateRandomValues(byteSize);
}

/**
 * Generates random value to be used as salt with encryption algorithms,
 * a salt is random data fed as an additional input to a one-way function that hashes data, a password or passphrase,
 * should at least 8 bytes to allow for 2^64 possible variations.
 *
 * @param byteSize The byte size of the generated random value.
 * @returns The random value
 */
export function generateSalt(byteSize = 8): Uint8Array {
  return generateRandomValues(byteSize);
}

export function generateHash(
  data: string | BufferSource,
  algorithm: string | Algorithm = 'SHA-256'
): Promise<ArrayBuffer> {
  return Promise.resolve(
    getCryptoObject().subtle.digest(algorithm, encode(data))
  );
}
