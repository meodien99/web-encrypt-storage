import { IDBPDatabase } from "idb";

export type InputDataType = BufferSource | string;

export interface IStorageConfig {
  key: InputDataType | CryptoKey;
  // data base name used to store data
  db?: string;
  name?: string;
  // salt used to encrypt the stored data.
  salt?: BufferSource;
  // iteration cycles to encrypt the stored data.
  iterations?: number;
  log?: boolean;
}

export type IConfigProperties = [IDBPDatabase<any>, string, CryptoKey, BufferSource, number | undefined];
