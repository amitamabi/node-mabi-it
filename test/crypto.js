const encryption = require('../built/encryption');

const { Buffer } = require('buffer');
const assert = require('assert/strict');

function testDecodeHead() {
    let key = encryption.generateHeaderKey("data_00000.it")
    let ciphered_text = new Uint8Array([
        0x37, 0x62, 0x6D, 0x63, 0x82, 0x03, 0x09, 0xD0, 0x24, 0x73, 0xBE, 0xA9,
    ]);
    let buf = Buffer.from(ciphered_text.buffer)
    let decrypted = encryption.decryptDataFromBuffer(buf, key);

    let rd = Buffer.from(decrypted)
    assert.strictEqual(rd.readUInt32LE(), 0x4b5)
    assert.strictEqual(rd.readUInt8(4), 2)
    assert.strictEqual(rd.readUInt32LE(5), 0x4b3)
}

function testHeaderKey() {
    let key = encryption.generateHeaderKey("data_00000.it")
    assert.deepStrictEqual(key, new Uint8Array([
        0x64, 0x62, 0x76, 0x64, 0x63, 0x35, 0x36, 0x37, 0x38, 0x39, 0x38, 0x74, 0x80, 0x4d,
        0x44, 0x60
    ]))
}

function test4byteHead() {
    let key = encryption.generateHeaderKey("data_00000.it")
    let ciphered_text = new Uint8Array([
        0x37, 0x62, 0x6D, 0x63, 0x82, 0x03, 0x09, 0xD0, 0x24, 0x73, 0xBE, 0xA9
    ]);
    let buf = Buffer.from(ciphered_text.buffer)
    let decrypted = encryption.decryptDataFromBuffer(buf, key);
}

function testDecodeEntries() {
    const key = encryption.generateEntriesKey("data_00000.it")
    const ciphered_text = new Uint8Array([
        0x8B, 0xD6, 0xBF, 0xE6, 0xAD, 0x7E, 0xE9, 0xE7, 0x64, 0x95, 0xF0, 0xBB, 0x08, 0x0E,
        0x89, 0x2D, 0xEE, 0x7A, 0x1E, 0x93, 0x16, 0x2B, 0x92, 0xCC, 0x20, 0x43, 0x2D, 0xE3,
        0x69, 0x1A, 0x65, 0xB3
    ])
    const decrypted = encryption.decryptDataFromBuffer(ciphered_text, key)
    assert.deepStrictEqual(decrypted, new Uint8Array([
        31, 0, 0, 0, 0x64, 0x0, 0x61, 0x0, 0x74, 0x0, 0x61, 0x0, 0x2f, 0x0, 0x63, 0x0, 0x6f, 0x0, 0x6c,
        0x0, 0x6f, 0x0, 0x72, 0x0, 0x2f, 0x0, 0x62, 0x0, 0x65, 0x0, 0x73, 0x0
    ]))

}
function testHeaderOffset() {
    let offset = encryption.generateHeaderOffset("data_00000.it")
    assert.strictEqual(offset, 0x6a)
}
function generateEntriesOffset() {
    let offset = encryption.generateEntriesOffset("data_00000.it")
    assert.strictEqual(offset, 0x6e)
}
function testEncrypt(){
    let encBuff = new Uint8Array([0,0,0,0])
    let magic = new Uint8Array([
        241, 211, 255, 132,  67,
         41, 119,  50, 134,  45,
        242,  29, 196, 229, 114,
         98
      ])
    let oc = new Uint8Array( [ 252, 194, 178, 235 ])
    let key = encryption.generateFileKey('data/color/black.raw',magic)
    console.log(key)
    let equalkey = new Uint8Array([236, 23, 94, 236, 107, 166, 236, 207, 77, 191, 214, 75, 108, 183, 118, 219])
    assert.deepStrictEqual(key, equalkey)
    let encrypted = encryption.encryptDataFromBuffer(encryption.encryptDataFromBuffer(encBuff, key), key)
    console.log(encrypted)
    assert.deepStrictEqual(oc,encrypted)
}

function testEncodeHead() {
    let key = encryption.generateHeaderKey("data_00000.it")
    let ciphered_text = new Uint8Array([
        0x37, 0x62, 0x6D, 0x63, 0x82, 0x03, 0x09, 0xD0, 0x24, 0x73, 0xBE, 0xA9,
    ]);
    let buf = Buffer.from(ciphered_text.buffer)
    let decrypted = encryption.decryptDataFromBuffer(buf, key);
    let encrypted = encryption.encryptDataFromBuffer(decrypted, key);
    assert.deepStrictEqual(encrypted, ciphered_text)
    // let rd = Buffer.from(decrypted)
    // assert.strictEqual(rd.readUInt32LE(), 0x4b5)
    // assert.strictEqual(rd.readUInt8(4), 2)
    // assert.strictEqual(rd.readUInt32LE(5), 0x4b3)

}
testHeaderKey()
testDecodeHead()
testDecodeEntries()

generateEntriesOffset()
testHeaderOffset() 
testEncodeHead()
testEncrypt()
