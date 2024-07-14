/**
 * Almost types are defined at
 * @source: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto
*/

/**
 * Import Key Algorithms Type
 */
export type ImportAlgorithm = AlgorithmIdentifier | AesKeyAlgorithm | HmacImportParams | RsaHashedImportParams | EcKeyImportParams;

/**
 * Derive Algorithms Params
 */
export type DeriveAlgorithmParam = AlgorithmIdentifier | AesDerivedKeyParams | HmacImportParams | Pbkdf2Params | HkdfParams;

/**
 * Derive Key Algorithms Type
 */
export type DeriveAlgorithm = AlgorithmIdentifier | EcdhKeyDeriveParams | Pbkdf2Params | HkdfParams;

/**
 * Params for Encrypt / Decrypt Algorithms
 */
export type AlgorithmParam = AlgorithmIdentifier | RsaOaepParams | AesCbcParams | AesGcmParams | AesCtrParams;

/**
 * Key Usages
 * @source: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#keyusages
 */
export type KeyUsage = 'encrypt' | 'decrypt' | 'sign' | 'verify' | 'deriveKey' | 'deriveBits' | 'wrapKey' | 'unwrapKey';
