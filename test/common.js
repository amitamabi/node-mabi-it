const encryption = require('../built/encryption');
const common = require('../built/common');
const assert = require('assert/strict');
const fs = require('fs');
function testReadHead(){
    let key = encryption.generateHeaderKey("data_00000.it","@6QeTuOaDgJlZcBm#9")
    let ciphered_text = new Uint8Array([
        0x37, 0x62, 0x6D, 0x63, 0x82, 0x03, 0x09, 0xD0, 0x24, 0x73, 0xBE, 0xA9,
    ]);
    let buf = Buffer.from(ciphered_text.buffer)
    let decrypted = encryption.decryptDataFromBuffer(buf, key);
    let fh = common.FileHeader.fromBuffer(decrypted)
    console.log(fh)
    assert.strictEqual(fh.version, 2)
    assert.strictEqual(fh.fileCount, 0x4b3)
    assert.strictEqual(fh.checksum, 0x4b5)
    fh.verify()
    assert.deepStrictEqual(fh.toBuffer(), new Uint8Array([
        181, 4, 0, 0, 2,
        179, 4, 0, 0, 0,0,0
    ]))
}
function bytesArrToBase64(arr) {
    const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // base64 alphabet
    const bin = n => n.toString(2).padStart(8,0); // convert num to 8-bit binary string
    const l = arr.length
    let result = '';
  
    for(let i=0; i<=(l-1)/3; i++) {
      let c1 = i*3+1>=l; // case when "=" is on end
      let c2 = i*3+2>=l; // case when "=" is on end
      let chunk = bin(arr[3*i]) + bin(c1? 0:arr[3*i+1]) + bin(c2? 0:arr[3*i+2]);
      let r = chunk.match(/.{1,6}/g).map((x,j)=> j==3&&c2 ? '=' :(j==2&&c1 ? '=':abc[+('0b'+x)]));  
      result += r.join('');
    }
  
    return result;
}
function readEntriesFromFile(){
    let buffer = new Uint8Array(fs.readFileSync("./data_70003.it"))
    let header = common.FileHeader.readEncryptHeader("data_70003.it",buffer)
    console.log(header)
    let entries = common.FileEntry.readEntries("data_70003.it",header,buffer)
    let size = entries.reduce((a,b)=>a+b.toBuffer().byteLength,0)
    let a = entries.map(e=>e.name)
    //console.log(a.join("\n"))
    console.log(JSON.stringify({entries},'\t'))
    //entries.map(e=>{console.log(`${e.name},${e.rawSize},${e.flags}`)})
}

function readEntriesFromFile1(){
    let buffer = new Uint8Array(fs.readFileSync("./data_01009.it"))
    let header = common.FileHeader.readEncryptHeader("data_01009.it",buffer)
    console.log(header)
    let entries = common.FileEntry.readEntries("data_01009.it",header,buffer,header.keySalt)
    let size = entries.reduce((a,b)=>a+b.toBuffer().byteLength,0)
    let a = entries.map(e=>e.name)
    //console.log(a.join("\n"))
    console.log(JSON.stringify({entries},'\t'))
    //entries.map(e=>{console.log(`${e.name},${e.rawSize},${e.flags}`)})
}
testReadHead()

readEntriesFromFile()
readEntriesFromFile1()