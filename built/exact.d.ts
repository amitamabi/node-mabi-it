import { FileEntry } from "./common";
export declare class RawFileEntry {
    originalEntry: FileEntry;
    content: Uint8Array;
    encodedContent: Uint8Array;
    /**
     *
     * @param {Uint8Array} buf
     * @param {number} startOff
     * @param {FileEntry} entry
     */
    static fromEncryptedPackedBuffer(buf: Uint8Array, startOff: number, entry: FileEntry): RawFileEntry;
    convertBuffer(): void;
}
/**
 * Exacting All Files From Buffer.
 * @param filename - *.it File's filename.
 * @param buf - File's buffer.
 * @returns Original File List
 */
export declare function exactFilesFromBuffer(filename: string, buf: Uint8Array): RawFileEntry[];
