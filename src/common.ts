import encryption = require("./encryption")
interface FileEntryObject {
    name: string;
    checksum: number;
    flags: number;
    offset: number;
    originalSize: number;
    rawSize: number;
    key: Uint8Array;
    
}
interface FileHeaderObject{
    checksum:number;
    version:number;
    fileCount:number;
}
export class FileHeader {
    checksum!: number;
    version!: number;
    fileCount!: number;
    static fromBuffer(buffer: Uint8Array): FileHeader {
        //input a uint8 arraybuffer
        let copiedBuffer = Uint8Array.prototype.slice.call(buffer)
        let dataView = new DataView(copiedBuffer.buffer)
        let fh = new FileHeader()
        fh.checksum = dataView.getUint32(0, true)
        fh.version = dataView.getUint8(4)
        fh.fileCount = dataView.getUint32(5, true)
        return fh
    }
    static fromValues(checksum:number, version:number, fileCount:number): FileHeader {
        let fh = new FileHeader()
        fh.checksum = checksum
        fh.version = version
        fh.fileCount = fileCount
        return fh
    }
    static fromObject(obj:FileHeaderObject): FileHeader {
        let fh = new FileHeader()
        fh.checksum = obj.checksum
        fh.version = obj.version
        fh.fileCount = obj.fileCount
        return fh
    }
    /**
     * 
     * @param {string}name - filename
     * @param {Uint8Array}buffer - origin file buffer
     * @returns {FileHeader} This is Decoded File Header;
     */
    static readEncryptHeader(filename:string, buffer:Uint8Array): FileHeader {
        let key = encryption.generateHeaderKey(filename)
        let headerOffset = encryption.generateHeaderOffset(filename)
        let cursor = headerOffset 
        let buf = buffer.slice(cursor, cursor+12)
        let decryptedBuffer = encryption.decryptDataFromBuffer(buf, key)
        let header = FileHeader.fromBuffer(decryptedBuffer)
        header.verify()
        return header
    }
    toBuffer():Uint8Array {
        let buffer = new ArrayBuffer(12)//encrypt padding.
        let dataView = new DataView(buffer)
        dataView.setUint32(0, this.checksum, true)
        dataView.setUint8(4, this.version)
        dataView.setUint32(5, this.fileCount, true)
        return new Uint8Array(buffer)
    }
    verify():boolean {
        if (this.version + this.fileCount != this.checksum){
            throw new Error("Invalid File Header")
        }else{
            return true
        }
    }
}

export class FileEntry{
    name!: string;
    checksum!: number;
    flags!: number;
    offset!: number;
    originalSize!: number;
    rawSize!: number;
    key!: Uint8Array;
    

    static fromBuffer(buf:Uint8Array):FileEntry{
        let copiedBuffer = Uint8Array.prototype.slice.call(buf)
        let dataView = new DataView(copiedBuffer.buffer)
        let entry = new FileEntry()
        let cursor = 0
        let strlen = dataView.getUint32(cursor, true);
        cursor += 4
        let fnameArray = []
        for(let i=0;i<strlen;i++){
            let a = dataView.getUint16(cursor, true)
            fnameArray.push(a)
            cursor += 2
        }
        entry.name = String.fromCharCode(...fnameArray)
        entry.checksum = dataView.getUint32(cursor, true)
        cursor += 4
        entry.flags = dataView.getUint32(cursor, true)
        cursor += 4
        entry.offset = dataView.getUint32(cursor, true)
        cursor += 4
        entry.originalSize = dataView.getUint32(cursor, true)
        cursor += 4
        entry.rawSize = dataView.getUint32(cursor, true)
        cursor += 4
        entry.key = new Uint8Array(dataView.buffer.slice(cursor, cursor+16))
        return entry
    }
    static fromObject(obj:FileEntryObject): FileEntry {
        let entry = new FileEntry()
        entry.name = obj.name
        entry.checksum = obj.checksum
        entry.flags = obj.flags
        entry.offset = obj.offset
        entry.originalSize = obj.originalSize
        entry.rawSize = obj.rawSize
        entry.key = obj.key
        return entry
    }
    /**
    * 
    * @param {string}name - filename
    * @param {FileHeader}header - file header
    * @param {Uint8Array}buffer - origin file buffer
    * @returns {FileEntry[]} This is Decoded File Entries;
    */
    static readEntries(filename:string, fileHeader:FileHeader, buffer:Uint8Array): FileEntry[] {
        let key = encryption.generateEntriesKey(filename)
        let headerOffset = encryption.generateHeaderOffset(filename)
        let entryOffset = encryption.generateEntriesOffset(filename)
        let cursor = 0
        let buf = buffer.slice(headerOffset + entryOffset, buffer.length-buffer.length%4)
        let decryptedBuffer = encryption.decryptDataFromBuffer(buf, key)
        let fileEntryArray = []
        for(let i=0;i<fileHeader.fileCount;i++){
            let entry = FileEntry.fromBuffer(decryptedBuffer.slice(cursor, decryptedBuffer.length))
            entry.verify()
            fileEntryArray.push(entry) 
            cursor += entry.toBuffer().byteLength
        }
        return fileEntryArray
    }
    static readonly FLAG_COMPRESSED = 1
    static readonly FLAG_ALL_ENCRYPTED = 2
    static readonly FLAG_HEAD_ENCRYPTED = 4
    toBuffer():Uint8Array {
        let strlen = this.name.length
        let buffer = new ArrayBuffer(4 + strlen * 2 + 20 + 16)
        let dataView = new DataView(buffer)
        let cursor =0
        dataView.setUint32(cursor, strlen, true)
        cursor += 4
        for(let i=0;i<strlen;i++){
            dataView.setUint16(cursor, this.name.charCodeAt(i), true)
            cursor += 2
        }
        dataView.setUint32(cursor, this.checksum, true)
        cursor += 4
        dataView.setUint32(cursor, this.flags, true)
        cursor += 4
        dataView.setUint32(cursor, this.offset, true)
        cursor += 4
        dataView.setUint32(cursor, this.originalSize, true)
        cursor += 4
        dataView.setUint32(cursor, this.rawSize, true)
        cursor += 4
        for(let i=0;i<this.key.length;i++){
            dataView.setUint8(cursor, this.key[i])
            cursor++
        }
        return new Uint8Array(buffer)
    }
    toJSON(){
        let obj = {} as any //Don't ask me why I have to do this.
        obj.name = this.name
        obj.checksum = this.checksum
        obj.flags = this.flags
        obj.offset = this.offset
        obj.originalSize = this.originalSize
        obj.rawSize = this.rawSize
        obj.key = bytesArrToBase64(this.key)
        return obj
    }
    verify():boolean {
        let key_sum = this.key.reduce((a,b)=>a+b)
        if(this.flags + this.offset + this.originalSize + this.rawSize + key_sum != this.checksum){
            throw new Error("Invalid File Entry")
        }else{
            return true
        }
    }
}
 

function bytesArrToBase64(arr:Uint8Array):string {
    const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // base64 alphabet
    const bin = (n: any) => n.toString(2).padStart(8,0); // convert num to 8-bit binary string
    const l = arr.length
    let result = '';
  
    for(let i=0; i<=(l-1)/3; i++) {
      let c1 = i*3+1>=l; // case when "=" is on end
      let c2 = i*3+2>=l; // case when "=" is on end
      let chunk = bin(arr[3*i]) + bin(c1? 0:arr[3*i+1]) + bin(c2? 0:arr[3*i+2]);
      let r = chunk.match(/.{1,6}/g).map((x:any,j:any)=> j==3&&c2 ? '=' :(j==2&&c1 ? '=':abc[+('0b'+x)]));  
      result += r.join('');
    }
  
    return result;
}

module.exports={
    FileHeader,FileEntry
}