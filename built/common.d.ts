interface FileEntryObject {
    name: string;
    checksum: number;
    flags: number;
    offset: number;
    originalSize: number;
    rawSize: number;
    key: Uint8Array;
}
interface FileHeaderObject {
    checksum: number;
    version: number;
    fileCount: number;
}
export declare class FileHeader {
    checksum: number;
    version: number;
    fileCount: number;
    static fromBuffer(buffer: Uint8Array): FileHeader;
    static fromValues(checksum: number, version: number, fileCount: number): FileHeader;
    static fromObject(obj: FileHeaderObject): FileHeader;
    /**
     *
     * @param {string}name - filename
     * @param {Uint8Array}buffer - origin file buffer
     * @returns {FileHeader} This is Decoded File Header;
     */
    static readEncryptHeader(filename: string, buffer: Uint8Array): FileHeader;
    toBuffer(): Uint8Array;
    verify(): boolean;
}
export declare class FileEntry {
    name: string;
    checksum: number;
    flags: number;
    offset: number;
    originalSize: number;
    rawSize: number;
    key: Uint8Array;
    static fromBuffer(buf: Uint8Array): FileEntry;
    static fromObject(obj: FileEntryObject): FileEntry;
    /**
    *
    * @param {string}filename - filename
    * @param {FileHeader}fileHeader - file header
    * @param {Uint8Array}buffer - origin file buffer
    * @returns {FileEntry[]} This is Decoded File Entries;
    */
    static readEntries(filename: string, fileHeader: FileHeader, buffer: Uint8Array): FileEntry[];
    static readonly FLAG_COMPRESSED = 1;
    static readonly FLAG_ALL_ENCRYPTED = 2;
    static readonly FLAG_HEAD_ENCRYPTED = 4;
    toBuffer(): Uint8Array;
    toJSON(): any;
    verify(): boolean;
}
export {};
