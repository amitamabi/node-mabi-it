const encryption = require('../built/encryption');

const assert = require('assert/strict');
const fs = require('fs');

class FileHeader {
    static fromBuffer(buffer) {
        //input a uint8 arraybuffer
        let copiedBuffer = Uint8Array.prototype.slice.call(buffer);
        let dataView = new DataView(copiedBuffer.buffer);
        let fh = new FileHeader();
        fh.checksum = dataView.getUint32(0, false);
        fh.version = dataView.getUint8(4);
        fh.fileCount = dataView.getUint32(5, false);
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

function testReadHead(){
    let key = encryption.generateHeaderKey("data_00000.it")
    let filebuf = fs.readFileSync("data_00000.it")
    for(i=0;i<1024;i++){
        let buf = filebuf.slice(i,i+12)
        let decrypted = encryption.decryptDataFromBuffer(Uint8Array.prototype.slice.call(buf), key);
        let fh = FileHeader.fromBuffer(decrypted)
        //console.log(fh)
        if(fh.version<1000){
            try{

                console.log(fh)
            }catch(e){

            }
        }
    }

}
testReadHead()