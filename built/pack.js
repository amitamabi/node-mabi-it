"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.packToNewBuffer = void 0;
const util_1 = require("util");
const common_1 = require("./common");
const encryption = require("./encryption");
function celi1024(v) {
    return Number(BigInt(v + 1023) & BigInt.asUintN(64, (BigInt(0) - BigInt(1024))));
}
function mergeUint8Array(arrays) {
    let length = arrays.reduce((a, b) => a + b.length, 0);
    let result = new Uint8Array(length);
    let offset = 0;
    arrays.map(function (array) {
        result.set(array, offset);
        offset += array.length;
    });
    return result;
}
/**
 *
 * @param {RawFileEntry[]} entries
 * @param {String} filename - output filename
 * @returns {Uint8Array}
 */
function packToNewBuffer(entries, filename) {
    let headerOffset = encryption.generateHeaderOffset(filename);
    let entryOffset = encryption.generateEntriesOffset(filename);
    let headerKey = encryption.generateHeaderKey(filename);
    let entriesKey = encryption.generateEntriesKey(filename);
    //遍历一下entries数组 拿一下长度，然后计算出contentStartOff.
    //别问我为什么这个时候调用，这是个除了字符串以外都定长的结构。
    //let contentStart = headerOffset + entryOffset + entries.reduce((a,b)=>a+b.originalEntry.toBuffer().byteLength,0)
    let contentStartOffset = celi1024(headerOffset + entryOffset + entries.reduce((a, b) => a + b.originalEntry.toBuffer().byteLength, 0));
    //第一次遍历 调用RawFileEntry.convertBuffer()方法进行编码
    //这个编码过程会根据flags参数决定是否压缩和加密，另:如果要压缩的话，会自动计算出压缩后的大小到rawSize里。
    entries.map(function (entry) {
        entry.convertBuffer();
    });
    //第二次遍历 通过rawSize计算对象内offset
    //定义一个临时变量
    let content_off = contentStartOffset;
    //ent.offset = ((content_off - start_content_off) / 1024) as u32;
    entries.map(function (entry) {
        entry.originalEntry.offset = Math.ceil((content_off - contentStartOffset) / 1024);
        content_off += (entry.originalEntry.rawSize >= 1024) ? entry.originalEntry.rawSize : 1024;
    });
    //第三次遍历 将entries数组转化为buffer，并创建一个足够容下的buffer
    let buffer = new Uint8Array(contentStartOffset + entries[entries.length - 1].originalEntry.offset * 1024 + entries[entries.length - 1].originalEntry.rawSize);
    //生成文件头并拷贝到buffer
    let fileHeader = common_1.FileHeader.fromObject({
        checksum: entries.length + 2,
        version: 2,
        fileCount: entries.length
    });
    //校验一哈
    fileHeader.verify();
    //加密并写入
    let fileHeaderBuffer = encryption.encryptDataFromBuffer(fileHeader.toBuffer(), headerKey);
    buffer.set(fileHeaderBuffer, headerOffset);
    //遍历entries数组,对每个entry生成校验值
    entries.map(function (entry) {
        entry.originalEntry.checksum = entry.originalEntry.offset + entry.originalEntry.rawSize + entry.originalEntry.originalSize + entry.originalEntry.flags + entry.originalEntry.key.reduce((a, b) => a + b);
    });
    //生成entries并拷贝到buffer
    let entriesBuffer = entries.map(function (entry) {
        return entry.originalEntry.toBuffer();
    });
    //align 4byte
    let entriesBufferMerged = mergeUint8Array(entriesBuffer);
    if (entriesBufferMerged.length % 4 != 0) {
        let entriesBufferMergedpadd = new Uint8Array(entriesBufferMerged.length + 4 - entriesBufferMerged.length % 4);
        entriesBufferMergedpadd.set(entriesBufferMerged);
        entriesBufferMerged = entriesBufferMergedpadd;
    }
    let entriesBufferEncrypted = encryption.encryptDataFromBuffer(entriesBufferMerged, entriesKey);
    buffer.set(entriesBufferEncrypted, headerOffset + entryOffset);
    //继续遍历 将encodedContent 拷贝到buffer
    entries.map(function (entry) {
        buffer.set(entry.encodedContent, contentStartOffset + entry.originalEntry.offset * 1024);
    });
    //按照mabi-pack2的惯例 在buffer前面加一个不加密的utf8的文件名,但是这个文件头
    let filenameBuffer = (new util_1.TextEncoder().encode(filename)).slice(0, headerOffset - 5);
    let magicBuffer = new util_1.TextEncoder().encode("YAT>\x0D");
    buffer.set(magicBuffer, 0);
    buffer.set(filenameBuffer, 5);
    return buffer;
}
exports.packToNewBuffer = packToNewBuffer;
module.exports = { packToNewBuffer };
