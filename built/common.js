"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FileEntry = exports.FileHeader = void 0;
const encryption = require("./encryption");
const KEY_SALT_LIST = [
    "3@6|3a[@<Ex:L=eN|g",
    "CuAVPMZx:E96:(Rxdw",
    "@6QeTuOaDgJlZcBm#9",
    "DaXU_Vx9xy;[ycFz{1",
    "}F33F0}_7X^;b?PM/;",
    "C(K^x&pBEeg7A5;{G9",
    "smh=Pdw+%?wk?m4&(y",
    "xGqK]W+_eM5u3[8-8u",
    "1&w2!&w{Q)Fkz4e&p0",
    "})wWb4?-sVGHNoPKpc"
];
class FileHeader {
    static fromBuffer(buffer) {
        //input a uint8 arraybuffer
        let copiedBuffer = Uint8Array.prototype.slice.call(buffer);
        let dataView = new DataView(copiedBuffer.buffer);
        let fh = new FileHeader();
        fh.checksum = dataView.getUint32(0, true);
        fh.version = dataView.getUint8(4);
        fh.fileCount = dataView.getUint32(5, true);
        return fh;
    }
    static fromValues(checksum, version, fileCount) {
        let fh = new FileHeader();
        fh.checksum = checksum;
        fh.version = version;
        fh.fileCount = fileCount;
        return fh;
    }
    static fromObject(obj) {
        let fh = new FileHeader();
        fh.checksum = obj.checksum;
        fh.version = obj.version;
        fh.fileCount = obj.fileCount;
        return fh;
    }
    /**
     *
     * @param {string}name - filename
     * @param {Uint8Array}buffer - origin file buffer
     * @returns {FileHeader} This is Decoded File Header;
     */
    static readEncryptHeader(filename, buffer) {
        let headerOffset = encryption.generateHeaderOffset(filename);
        let keySalt = testKeySalt(filename, buffer);
        let key = encryption.generateHeaderKey(filename, keySalt[0]);
        let buf = buffer.slice(headerOffset, headerOffset + 12);
        let decryptedBuffer = encryption.decryptDataFromBuffer(buf, key);
        let header = FileHeader.fromBuffer(decryptedBuffer);
        header.keySalt = keySalt;
        header.verify();
        return header;
    }
    toBuffer() {
        let buffer = new ArrayBuffer(12); //encrypt padding.
        let dataView = new DataView(buffer);
        dataView.setUint32(0, this.checksum, true);
        dataView.setUint8(4, this.version);
        dataView.setUint32(5, this.fileCount, true);
        return new Uint8Array(buffer);
    }
    verify() {
        if (this.version + this.fileCount != this.checksum) {
            throw new Error("Invalid File Header");
        }
        else {
            return true;
        }
    }
}
exports.FileHeader = FileHeader;
class FileEntry {
    static fromBuffer(buf) {
        let copiedBuffer = Uint8Array.prototype.slice.call(buf);
        let dataView = new DataView(copiedBuffer.buffer);
        let entry = new FileEntry();
        let cursor = 0;
        let strlen = dataView.getUint32(cursor, true);
        cursor += 4;
        let fnameArray = [];
        for (let i = 0; i < strlen; i++) {
            let a = dataView.getUint16(cursor, true);
            fnameArray.push(a);
            cursor += 2;
        }
        entry.name = String.fromCharCode(...fnameArray);
        entry.checksum = dataView.getUint32(cursor, true);
        cursor += 4;
        entry.flags = dataView.getUint32(cursor, true);
        cursor += 4;
        entry.offset = dataView.getUint32(cursor, true);
        cursor += 4;
        entry.originalSize = dataView.getUint32(cursor, true);
        cursor += 4;
        entry.rawSize = dataView.getUint32(cursor, true);
        cursor += 4;
        entry.key = new Uint8Array(dataView.buffer.slice(cursor, cursor + 16));
        return entry;
    }
    static fromObject(obj) {
        let entry = new FileEntry();
        entry.name = obj.name;
        entry.checksum = obj.checksum;
        entry.flags = obj.flags;
        entry.offset = obj.offset;
        entry.originalSize = obj.originalSize;
        entry.rawSize = obj.rawSize;
        entry.key = obj.key;
        return entry;
    }
    /**
    *
    * @param {string}name - filename
    * @param {FileHeader}header - file header
    * @param {Uint8Array}buffer - origin file buffer
    * @returns {FileEntry[]} This is Decoded File Entries;
    */
    static readEntries(filename, fileHeader, buffer, keySalt) {
        let headerOffset = encryption.generateHeaderOffset(filename);
        let entryOffset = encryption.generateEntriesOffset(filename);
        let ks;
        //test key salt array
        if (fileHeader.keySalt) {
            ks = fileHeader.keySalt.filter((ks) => {
                let key = encryption.generateEntriesKey(filename, ks);
                let buf = buffer.slice(headerOffset + entryOffset, headerOffset + entryOffset + 4096 - buffer.length % 4);
                let cursor = 0;
                let decryptedBuffer = encryption.decryptDataFromBuffer(buf, key);
                try {
                    let entry = FileEntry.fromBuffer(decryptedBuffer.slice(cursor, decryptedBuffer.length));
                    entry.verify();
                    return true;
                }
                catch (e) {
                    return false;
                }
            });
            ks = ks[0];
        }
        let key = encryption.generateEntriesKey(filename, ks);
        let cursor = 0;
        let buf = buffer.slice(headerOffset + entryOffset, buffer.length - buffer.length % 4);
        let decryptedBuffer = encryption.decryptDataFromBuffer(buf, key);
        let fileEntryArray = [];
        for (let i = 0; i < fileHeader.fileCount; i++) {
            let entry = FileEntry.fromBuffer(decryptedBuffer.slice(cursor, decryptedBuffer.length));
            entry.verify();
            fileEntryArray.push(entry);
            cursor += entry.toBuffer().byteLength;
        }
        return fileEntryArray;
    }
    toBuffer() {
        let strlen = this.name.length;
        let buffer = new ArrayBuffer(4 + strlen * 2 + 20 + 16);
        let dataView = new DataView(buffer);
        let cursor = 0;
        dataView.setUint32(cursor, strlen, true);
        cursor += 4;
        for (let i = 0; i < strlen; i++) {
            dataView.setUint16(cursor, this.name.charCodeAt(i), true);
            cursor += 2;
        }
        dataView.setUint32(cursor, this.checksum, true);
        cursor += 4;
        dataView.setUint32(cursor, this.flags, true);
        cursor += 4;
        dataView.setUint32(cursor, this.offset, true);
        cursor += 4;
        dataView.setUint32(cursor, this.originalSize, true);
        cursor += 4;
        dataView.setUint32(cursor, this.rawSize, true);
        cursor += 4;
        for (let i = 0; i < this.key.length; i++) {
            dataView.setUint8(cursor, this.key[i]);
            cursor++;
        }
        return new Uint8Array(buffer);
    }
    toJSON() {
        let obj = {}; //Don't ask me why I have to do this.
        obj.name = this.name;
        obj.checksum = this.checksum;
        obj.flags = this.flags;
        obj.offset = this.offset;
        obj.originalSize = this.originalSize;
        obj.rawSize = this.rawSize;
        obj.key = bytesArrToBase64(this.key);
        return obj;
    }
    verify() {
        let key_sum = this.key.reduce((a, b) => a + b);
        if (this.flags + this.offset + this.originalSize + this.rawSize + key_sum != this.checksum) {
            throw new Error("Invalid File Entry");
        }
        else {
            return true;
        }
    }
}
exports.FileEntry = FileEntry;
FileEntry.FLAG_COMPRESSED = 1;
FileEntry.FLAG_ALL_ENCRYPTED = 2;
FileEntry.FLAG_HEAD_ENCRYPTED = 4;
function bytesArrToBase64(arr) {
    const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // base64 alphabet
    const bin = (n) => n.toString(2).padStart(8, 0); // convert num to 8-bit binary string
    const l = arr.length;
    let result = '';
    for (let i = 0; i <= (l - 1) / 3; i++) {
        let c1 = i * 3 + 1 >= l; // case when "=" is on end
        let c2 = i * 3 + 2 >= l; // case when "=" is on end
        let chunk = bin(arr[3 * i]) + bin(c1 ? 0 : arr[3 * i + 1]) + bin(c2 ? 0 : arr[3 * i + 2]);
        let r = chunk.match(/.{1,6}/g).map((x, j) => j == 3 && c2 ? '=' : (j == 2 && c1 ? '=' : abc[+('0b' + x)]));
        result += r.join('');
    }
    return result;
}
function testKeySalt(filename, buffer) {
    let keySalt = [];
    let headerOffset = encryption.generateHeaderOffset(filename);
    for (let index = 0; index < KEY_SALT_LIST.length; index++) {
        const element = KEY_SALT_LIST[index];
        let key = encryption.generateHeaderKey(filename, element);
        let buf = buffer.slice(headerOffset, headerOffset + 12);
        let decryptedBuffer = encryption.decryptDataFromBuffer(buf, key);
        let header = FileHeader.fromBuffer(decryptedBuffer);
        try {
            header.verify();
            keySalt.push(element);
        }
        catch (e) {
        }
    }
    // KEY_SALT_LIST.forEach((ks) => {
    //     let headerOffset = encryption.generateHeaderOffset(filename)
    //     let key = encryption.generateHeaderKey(filename, ks)
    //     let buf = buffer.slice(headerOffset, headerOffset + 12)
    //     let decryptedBuffer = encryption.decryptDataFromBuffer(buf, key)
    //     let header = FileHeader.fromBuffer(decryptedBuffer)
    //     try {
    //         header.verify()
    //         console.log("Key Salt Found: " + ks)
    //         return ks
    //     } catch (e) {
    //     }
    // })
    return keySalt;
}
module.exports = {
    FileHeader, FileEntry
};
