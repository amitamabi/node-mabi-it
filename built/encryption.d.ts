/// <reference types="node" />
import { Buffer } from "buffer";
/**
 * Genreate Offset to Decrypt .it File Header.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {number} This is Genreated Offset;
 */
export declare function generateHeaderOffset(name: string): number;
/**
 * Genreate Key to Decrypt .it File Header.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {Uint8Array} This is Genreated Key;
 */
export declare function generateHeaderKey(name: string, keySalt?: string): Uint8Array;
/**
 * Genreate Key to Decrypt .it File Entries.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {Uint8Array} This is Genreated Key;
 */
export declare function generateEntriesKey(name: string, keySalt?: string): Uint8Array;
/**
 * Genreate Offset to Decrypt .it File Entries.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {number} This is Genreated Offset;
 */
export declare function generateEntriesOffset(name: string): number;
export declare function generateFileKey(name: string, key2: Uint8Array): Uint8Array;
/**
 * Decrypt Data From Buffer
 * @param {Uint8Array|Buffer}buf - Buffer to Decrypt;
 * @param {Uint8Array}key - Key to Decrypt, MUST LENGTH == 16;
 * @returns {Uint8Array} This is Decrypted Data;
 */
export declare function decryptDataFromBuffer(buf: (Uint8Array | Buffer), key: Uint8Array): Uint8Array;
/**
 * Encrypt Data From Buffer
 * @param {Uint8Array|Buffer}buf - Buffer to Encrypt;
 * @param {Uint8Array}key - Key to Encrypt, MUST LENGTH == 16;
 * @returns {Uint8Array} This is Encrypted Data;
 */
export declare function encryptDataFromBuffer(buf: (Uint8Array | Buffer), key: Uint8Array): Uint8Array;
