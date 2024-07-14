import { IDBPDatabase, deleteDB, openDB } from "idb";
import { decode, decrypt, deriveKey, encrypt, generateCryptoKey, generateHash, generateSalt } from "../crypto";
import { IStorageConfig, InputDataType, IConfigProperties } from "./storage.type";

export const CRYPTO_KEY_ERROR_MESSAGE = `Key is required.`;
export const AUTHENTICITY_ERROR_MESSAGE = `Authenticity check failed.`;

const getAndStoreSalt = async (
  storePromise: Promise<IDBPDatabase> | IDBPDatabase,
  name: string,
  salt?: BufferSource
): Promise<BufferSource> => {
  const hash = await generateHash('o-salt'); // original salt
  const store = await storePromise;
  // const [hash, store] = await Promise.all([generateHash('o-salt'), storePromise]);
  const existingSalt = await store.get(name, hash);

  if (existingSalt && (!salt || existingSalt === salt)) {
    return existingSalt;
  }

  // store salt
  const saltValue = salt ?? generateSalt();
  await store.put(name, saltValue, hash);

  return saltValue;
}

const getNonceKey = (key: InputDataType): string => {
  if (typeof key === 'string') {
    return `${key}-nonce`
  }

  return 'nonce'
};

export class EncryptStorage {
  private _properties: Promise<IConfigProperties>;

  /**
   *
   * @param config IStorageConfig
   * @param config.baseKey A cryptoKey
   * @param config.db database name used to store data. Default: <default-db>
   * @param config.name A name of store Default: <default-name>
   * @param salt A salt used to encrypt the stored data
   * @param iterations iteration cycles to encrypt the stored data
   */
  constructor(config: IStorageConfig) {
    if (!config.key) {
      throw new Error(CRYPTO_KEY_ERROR_MESSAGE);
    }

    this._properties = this._init(config);
  }

  private async _init({
    key,
    db = 'default-db',
    name = 'default-storage-name',
    salt,
    iterations
  }: IStorageConfig): Promise<IConfigProperties> {
    const dbHash = await generateHash(db);
    const storeHash = await generateHash(name);
    const baseKey = key instanceof CryptoKey ? key : await generateCryptoKey({ raw: key });

    const decodedStorageName = decode(storeHash);

    const store = openDB(decode(dbHash), 1, {
      upgrade(db) {
        db.createObjectStore(decodedStorageName);
      },
    });

    return Promise.all([
      store,
      decodedStorageName,
      baseKey,
      getAndStoreSalt(store, decodedStorageName, salt),
      iterations
    ]);
  }

  /**
   * Loads all and encrypt the stored data that match the given Key.
   *
   * @param key
   * @returns Promise of decoded data or undefined if nothing was found.
   */
  async get(key: InputDataType): Promise<string | undefined> {
    const [store, name, baseKey, salt, iterations] = await this._properties;
    const hashKey = await generateHash(key);
    const hashNonce = await generateHash(getNonceKey(key));

    const encrypted = await store.get(name, hashKey);

    if (!encrypted) {
      return undefined;
    }

    const cryptoKey = await deriveKey({ key: baseKey, saltOrDeriveAlgorithm: salt, iterationsOrAlgorithmParam: iterations });
    const nonce = await store.get(name, hashNonce);

    try {
      const value = await decrypt({ data: encrypted, key: cryptoKey, nonceOrAlgorithm: nonce });

      return decode(value);
    } catch (e) {
      throw new Error(AUTHENTICITY_ERROR_MESSAGE);
    }
  }

  async getDB(): Promise<IDBPDatabase<any>> {
    const [db] = await this._properties;

    return db;
  }

  async getStoreName(): Promise<string> {
    const [,store] = await this._properties;

    return store;
  }

  /**
   * Encrypt and save the given data and key.
   * @param key The key to be encrypted and indexed to find.
   * @param value The value to be encrypted and stored.
   * @returns Promise to know when the procession is completed.
   */
  async set(key: InputDataType, value: InputDataType): Promise<void> {
    const [store, name, baseKey, salt, iterations] = await this._properties;
    const hashKey = await generateHash(key);
    const hashNonce = await generateHash(getNonceKey(key));

    const cryptoKey = await deriveKey({ key: baseKey, saltOrDeriveAlgorithm: salt, iterationsOrAlgorithmParam: iterations });
    const [encrypted, nonce] = await encrypt({ data: value, key: cryptoKey });

    await store.put(name, encrypted, hashKey);
    await store.put(name, nonce, hashNonce);
  }

  /**
   * Clear all key and data but keeping the structure.
   *
   * @returns Promise to know when the process is completed.
   * */
  async clear(): Promise<void> {
    const [store, name, _, salt] = await this._properties;
    await store.clear(name);
    await getAndStoreSalt(store, name, salt);
  }

  /**
  * close database connection.
  *
  * @returns Promise to know when the process is completed.
  * */
  async close(): Promise<void> {
    const [store] = await this._properties;

    store.close();
  }

  /**
 * Delete a stored data by given key.
 *
 * @params key The key find.
 * @returns Promise to know when the process is completed.
 * */
  async delete(key: InputDataType): Promise<void> {
    const [store, name] = await this._properties;
    const hashKey = await generateHash(key);
    const hashNonce = await generateHash(getNonceKey(key));

    await store.delete(name, hashKey);
    await store.delete(name, hashNonce);
  }

  /**
   * Delete whole store & db structure
   *
   * @returns Promise to know when the process is completed.
   */
  async deleteDB(): Promise<void> {
    const [store] = await this._properties;

    store.close();
    await deleteDB(store.name);
  }
}
