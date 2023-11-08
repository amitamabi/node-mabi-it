"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.exactFilesFromBuffer = exports.RawFileEntry = void 0;
const encryption = require("./encryption");
const common_1 = require("./common");
const zlib_1 = __importDefault(require("zlib"));
class RawFileEntry {
    /**
     *
     * @param {Uint8Array} buf
     * @param {number} startOff
     * @param {FileEntry} entry
     */
    static fromEncryptedPackedBuffer(buf, startOff, entry) {
        let cursor = startOff + entry.offset * 1024;
        let key = encryption.generateFileKey(entry.name, entry.key);
        let contentBuffer = new Uint8Array(entry.rawSize);
        let fileFlag = {
            ALL_ENCRYPTED: entry.flags & common_1.FileEntry.FLAG_ALL_ENCRYPTED,
            HEAD_ENCRYPTED: entry.flags & common_1.FileEntry.FLAG_HEAD_ENCRYPTED,
            COMPRESSED: entry.flags & common_1.FileEntry.FLAG_COMPRESSED
        };
        if (fileFlag.ALL_ENCRYPTED != 0) {
            let decryptedBuffer = encryption.decryptDataFromBuffer(buf.slice(cursor, cursor + contentBuffer.byteLength), key);
            contentBuffer.set(decryptedBuffer);
        }
        else {
            contentBuffer.set(buf.slice(cursor, cursor + entry.rawSize));
        }
        if (fileFlag.HEAD_ENCRYPTED != 0) {
            let length = Math.min(contentBuffer.length, 1024);
            let decryptedBuffer = encryption.decryptDataFromBuffer(contentBuffer.slice(0, length), key);
            contentBuffer.set(decryptedBuffer);
        }
        if (fileFlag.COMPRESSED != 0) {
            contentBuffer = new Uint8Array(zlib_1.default.inflateSync(contentBuffer));
            if (contentBuffer.length != entry.originalSize) {
                throw new Error("original size not match");
            }
        }
        let rawFileEntry = new RawFileEntry();
        rawFileEntry.originalEntry = entry;
        rawFileEntry.content = contentBuffer;
        return rawFileEntry;
    }
    /**
     *  encode this file entry to encodedContent with flags
     *
     */
    convertBuffer() {
        let content = this.content.slice();
        let fileKey = encryption.generateFileKey(this.originalEntry.name, this.originalEntry.key);
        let fileFlag = {
            ALL_ENCRYPTED: this.originalEntry.flags & common_1.FileEntry.FLAG_ALL_ENCRYPTED,
            HEAD_ENCRYPTED: this.originalEntry.flags & common_1.FileEntry.FLAG_HEAD_ENCRYPTED,
            COMPRESSED: this.originalEntry.flags & common_1.FileEntry.FLAG_COMPRESSED
        };
        if (fileFlag.COMPRESSED != 0) {
            content = new Uint8Array(zlib_1.default.deflateSync(content, { level: 9 }));
        }
        if (fileFlag.HEAD_ENCRYPTED != 0) {
            let length = Math.min(content.length, 1024);
            content = encryption.encryptDataFromBuffer(content.slice(0, length), fileKey);
        }
        if (fileFlag.ALL_ENCRYPTED != 0) {
            //align 4byte
            let length = content.length;
            let padding = length % 4;
            if (padding != 0) {
                padding = 4 - padding;
                content = new Uint8Array(length + padding);
                content.set(this.content);
            }
            content = encryption.encryptDataFromBuffer(content, fileKey);
        }
        this.originalEntry.rawSize = content.length;
        this.encodedContent = content;
    }
}
exports.RawFileEntry = RawFileEntry;
/**
 * Exacting All Files From Buffer.
 * @param filename - *.it File's filename.
 * @param buf - File's buffer.
 * @returns Original File List
 */
function exactFilesFromBuffer(filename, buf) {
    let headerOffset = encryption.generateHeaderOffset(filename);
    let entryOffset = encryption.generateEntriesOffset(filename);
    let fileHeader = common_1.FileHeader.readEncryptHeader(filename, buf);
    console.log(fileHeader);
    let entries = common_1.FileEntry.readEntries(filename, fileHeader, buf);
    let currentPos = headerOffset + entryOffset + entries.reduce((a, b) => a + b.toBuffer().byteLength, 0);
    let contentStartOff = BigInt(currentPos + 1023) & BigInt.asUintN(64, (BigInt(0) - BigInt(1024))); //由于用了BigInt 平台支持可能会有问题。
    //console.log(contentStartOff)
    let rawFileEntries = entries.map(function (entry) {
        return RawFileEntry.fromEncryptedPackedBuffer(buf, Number(contentStartOff), entry);
    });
    return rawFileEntries;
}
exports.exactFilesFromBuffer = exactFilesFromBuffer;
module.exports = {
    RawFileEntry, exactFilesFromBuffer
};
