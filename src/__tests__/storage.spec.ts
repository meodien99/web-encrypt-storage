import { decode, generateCryptoKey, generateHash } from "../scripts/crypto";
import { AUTHENTICITY_ERROR_MESSAGE, EncryptStorage } from "../scripts/storage";


/**
 * Start Testcases
 * save the testcase into list so we can reset db after each.
*/
const list = new Set<EncryptStorage>();

const add = (item: EncryptStorage): EncryptStorage => {
  list.add(item);

  return item;
}

const clear = (): Promise<any> => {
  return Promise.all(
    Array.from(list).map(db => db.deleteDB().catch())
  ).finally(() => {
    list.clear()
  });
}

export async function catchAsyncErrorMessage(promise: Promise<any>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error: any) {
    return error.message;
  }
}

describe('EncryptStorage IDB tests', () => {
  afterEach(async () => {
    await clear();
  });

  describe('Creating Object Instance', () => {
    it('should not be able to save data without a crypto key', async () => {
      const init = async () => {
        return new EncryptStorage({ key: undefined as any });
      }

      expect(await catchAsyncErrorMessage(init())).toEqual("Key is required.");
    });
  })

  describe('Saving data', () => {
    it('should be able to save data with a raw crypto key', async () => {
      const test = add(new EncryptStorage({ key: 'raw key' }));
      await test.set('any key', 'any value');

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);

      expect(allKeys.length >= 1).toBeTrue();
    });

    it('should be able to save data with a crypto key', async () => {
      const key = await generateCryptoKey({ raw: 'rawkey' });
      const test = add(new EncryptStorage({ key }));
      await test.set('any key', 'any value');

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);

      expect(allKeys.length >= 1).toBeTrue();
    });

    it('should not save the raw data', async () => {
      const test = add(new EncryptStorage({ key: 'any key' }));
      const value = 'any value';
      await test.set('any key', value);

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);
      const values = await Promise.all(allKeys.map(k => db.get(dbStorageName, k)));

      const result = values.some((v) => v === value);

      expect(result).toBeFalse();
    });

    it('should not save the raw key', async () => {
      const test = add(new EncryptStorage({ key: 'any key' }));
      const ikey = 'any key';
      await test.set(ikey, 'any value');

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);
      const result = allKeys.some(k => k === ikey);

      expect(result).toBeFalse();
    });

    it('should not use the raw db name', async () => {
      const dbName = 'dbName';
      const test = add(new EncryptStorage({ key: 'any key' }));
      await test.set('any key', 'any value');

      const allDbs = await window.indexedDB.databases();
      const result = allDbs.some(({ name }) => name === dbName);

      expect(result).toBeFalse();
    });

    it('should not use the raw table name', async () => {
      const tableName = 'storeName';
      const test = add(new EncryptStorage({ key: 'any key' }));
      await test.set('any key', 'any value');

      const [, dbStorageName] = await test['_properties'];
      expect(tableName === dbStorageName).toBeFalse();
    });
  });

  describe('Getting data', () => {
    it('should get the original value', async () => {
      const test = add(new EncryptStorage({ key: 'any key' }));
      const ikey = 'any key';
      const value = 'any value';
      await test.set(ikey, value);

      expect(await test.get(ikey)).toEqual(value);
    });

    it('should get same value in another instance with same key', async () => {
      const key = 'any';
      const test1 = add(new EncryptStorage({ key }));
      const ikey = 'any key';
      const value = 'any value';

      await test1.set(ikey, value);
      const v1 = await test1.get(ikey);

      const test2 = add(new EncryptStorage({ key }));

      await test2.set(ikey, value);
      const v2 = await test2.get(ikey);

      expect(v1).toEqual(value);
      // getted values from test1.get() & test2.get() will be not equal because idb stored a new instance for KEY of test2.
      // so parsing test.get() will throw Exception
      expect(v1).toEqual(v2);
    });

    it('should get same value in another instance with same key and db name', async () => {
      const key = 'anykey';
      const dbName = 'anydb';
      const test1 = add(new EncryptStorage({ key, db: dbName }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      const test2 = add(new EncryptStorage({ key, db: dbName }));
      await test2.set(ikey, value);

      expect(await test2.get(ikey)).toEqual(value);
    });

    it('should get same value in another instance with same key and db name and table name', async () => {
      const key = 'anykey';
      const dbName = 'anydb';
      const tableName = 'anystore';
      const test1 = add(new EncryptStorage({ key, db: dbName, name: tableName }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      const test2 = add(new EncryptStorage({ key, db: dbName, name: tableName }));
      await test2.set(ikey, value);

      expect(await test2.get(ikey)).toEqual(value);
    });

    it('should get same value in another instance with same key, db name, table name and salt', async () => {
      const key = 'anykey';
      const dbName = 'anydb';
      const tableName = 'anystore';
      const salt = new Uint8Array([1, 2, 3, 4]);
      const test1 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      const test2 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt }));

      expect(await test2.get(ikey)).toEqual(value);
    });

    it('should get same value in another instance with same key, db name, table name, salt and iterations', async () => {
      const key = 'anykey';
      const dbName = 'anydb';
      const tableName = 'anystore';
      const iterations = 100;
      const salt = new Uint8Array([1, 2, 3, 4]);
      const test1 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt, iterations }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      const test2 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt, iterations }));

      expect(await test2.get(ikey)).toEqual(value);
    });

    it('should not get stored values from another databases with a same key', async () => {
      const key = 'anykey';
      let test1 = add(new EncryptStorage({ key, db: 'db1' }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      test1 = add(new EncryptStorage({ key, db: 'db2' }));

      expect(await test1.get(ikey)).toBeUndefined();
    });

    it('should not able to load data stored with a different key', async () => {
      const test1 = add(new EncryptStorage({ key: 'key1' }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      const test2 = add(new EncryptStorage({ key: 'key2' }));

      expect(await catchAsyncErrorMessage(test2.get(ikey))).toEqual(AUTHENTICITY_ERROR_MESSAGE);
    });

    it('should not get stored values from another salts with a same key, db, storeName', async () => {
      const dbName = 'anydb';
      const tableName = 'anyStore';
      const key = 'anyKey';
      let test1 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt: new Uint8Array([1, 2, 3]) }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      test1 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt: new Uint8Array([1, 22, 13]) }));

      expect(await catchAsyncErrorMessage(test1.get(ikey))).toEqual(AUTHENTICITY_ERROR_MESSAGE);
    });

    it('should not get stored values from another iterations with a same key, db, storeName and salts', async () => {
      const dbName = 'anydb';
      const tableName = 'anyStore';
      const key = 'anyKey';
      const salt = new Uint8Array([1, 2, 3]);
      let test1 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt, iterations: 123 }));
      const ikey = 'any key';
      const value = 'any value';
      await test1.set(ikey, value);

      test1 = add(new EncryptStorage({ key, db: dbName, name: tableName, salt, iterations: 1213 }));

      expect(await catchAsyncErrorMessage(test1.get(ikey))).toEqual(AUTHENTICITY_ERROR_MESSAGE);
    });
  });

  describe('Clearing data', () => {
    it('should clear all existing data but the salt', async () => {
      const test = add(new EncryptStorage({ key: 'any key' }));
      await test.set('any key 1', 'any data 1');
      await test.set('any key 2', 'any data 2');
      await test.clear();

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);
      let result = allKeys.length !== 1;

      if(!result) {
        const saltHash = await generateHash('o-salt');
        result = decode(allKeys[0]) === decode(saltHash)
      }

      expect(result).toBeTrue();
    });

    it('should not delete the store', async () => {
      const test = add(new EncryptStorage({ key: 'any key' }));
      await test.set('any key', 'any data');
      await test.clear();

      const [db] = await test['_properties'];

      expect(db.objectStoreNames.length !== 0).toBeTrue();
    });

    it('should not delete the db', async () => {
      const test = add(new EncryptStorage({ key: 'any key' }));
      await test.set('any key', 'any data');
      await test.clear();
      const allDbs = await window.indexedDB.databases();

      expect(allDbs.length !== 0).toBeTrue();
    });

    it('should be able to set new values after clearing and get it from another instance', async () => {
      const key = 'raw key';
      const ikey = 'any key';
      const value = 'any value';
      let test = add(new EncryptStorage({ key, log: true }));
      await test.set(ikey, value);
      await test.clear();
      await test.set(ikey, value);
      test = add(new EncryptStorage({ key }));

      expect(await test.get(ikey)).toBe(value);
    });
  });

  describe('when deleting individual data', () => {
    it('should keep the salt even if it deletes the only existing data', async () => {
      const test = add(new EncryptStorage({ key: 'any' }));
      const key = 'any key 1';
      await test.set(key, 'any data 1');
      await test.delete(key);

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);
      let result = allKeys.length !== 1;

      if(!result) {
        const saltHash = await generateHash('o-salt');
        result = decode(allKeys[0]) === decode(saltHash)
      }

      expect(result).toBeTrue();
    });

    it('should delete data only for the giving key', async () => {
      const test = add(new EncryptStorage({ key: 'any' }));
      const key = 'any key 1';
      await test.set(key, 'any data 1');
      await test.set('any key 2', 'any data 2');
      await test.delete(key);
      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);

      expect(allKeys.length >= 1).toBeTrue();
    });

    it('should be able to set new data after deleting one', async () => {
      const test = add(new EncryptStorage({ key: 'any' }));
      const key = 'any key 1';
      await test.set(key, 'any data 1');
      await test.delete(key);
      await test.set('any key 2', 'any data 2');

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);

      expect(allKeys.length >= 1).toBeTrue();
    });

    it('should not be able to get the deleted data from another instance', async () => {
      const key = 'raw key';
      const ikey = 'any key';
      let test1 = add(new EncryptStorage({ key }));
      await test1.set(ikey, 'any data');
      await test1.delete(ikey);
      const test2 = add(new EncryptStorage({ key }));
      expect(await test2.get(ikey)).toBeUndefined();
    });
  });

  describe('when deleting the database', () => {
    it('should delete the data base', async () => {
      const test = new EncryptStorage({ key: 'any key' });
      await test.set('any key', 'any data');
      await test.deleteDB();
      const allDbs = await window.indexedDB.databases();

      expect(allDbs.length !== 0).toBeFalsy();
    });
  });

  describe('when closing the database', () => {
    it('should have close the database with saved data', async () => {
      let test = new EncryptStorage({ key: 'any key' });
      await test.set('any key', 'any data');
      await test.close();
      test = add(new EncryptStorage({ key: 'any key' }));

      const [db, dbStorageName] = await test['_properties'];
      const allKeys = await db.getAllKeys(dbStorageName);

      expect(allKeys.length >= 1).toBeTrue();
    });
  });
});
