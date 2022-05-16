import { RawFileEntry } from "./exact";
/**
 *
 * @param {RawFileEntry[]} entries
 * @param {String} filename - output filename
 * @returns {Uint8Array}
 */
export declare function packToNewBuffer(entries: RawFileEntry[], filename: string): Uint8Array;
