const fs = require("fs");
const common = require("../built/common");
const encryption = require("../built/encryption");
charlist = ["3@6|3a[@<Ex:L=eN|g",
"CuAVPMZx:E96:(Rxdw",
"@6QeTuOaDgJlZcBm#9",
"DaXU_Vx9xy;[ycFz{1",
"}F33F0}_7X^;b?PM/;",
"C(K^x&pBEeg7A5;{G9",
"smh=Pdw+%?wk?m4&(y",
"xGqK]W+_eM5u3[8-8u",
"1&w2!&w{Q)Fkz4e&p0",
"})wWb4?-sVGHNoPKpc"]
const saltlist = charlist



function generateHeaderKey(name,KEY_SALT){
	let input = new Uint16Array((name.toLowerCase()+KEY_SALT).split("").map(c=>c.charCodeAt(0)))
	let key = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		key[i] = input[i%input.length] + i;
	}
	return key
}
function generateEntriesKey(name,KEY_SALT){
	let input = new Uint16Array((name.toLowerCase()+KEY_SALT).split("").map(c=>c.charCodeAt(0)))
	let key = new Uint8Array(16);
	let len = input.length
	for (let i = 0; i < 16; i++) {
		key[i] = (i + (i%3+2) * input[len - 1 - i % len]) %256
	}
	return key
}

function testReadHead(){
    let buf = new Uint8Array(fs.readFileSync("./data_01009.it"))
    //for(let i=0;i<buf.length - 12;i++){
        let headerOffset = encryption.generateHeaderOffset("data_01009.it")
        saltlist.forEach(element => {
            let key = generateHeaderKey("data_01009.it",element)
            let decrypted = encryption.decryptDataFromBuffer(buf.slice(headerOffset,headerOffset+12) ,key);
            //let decrypted = encryption.decryptDataFromBuffer(buf.slice(i,i+12), key);
            let fh = common.FileHeader.fromBuffer(decrypted)
            try{
                fh.verify()
                console.log(fh,element)
                testReadEntire(element,buf,"data_01009.it",fh)
            }catch(e){
                
            }
        });
    //}
}
const {FileEntry} = require("../built/common")
function testReadEntire(keySalt,filebuf,fn,header){
    function readEntries(filename, fileHeader, buffer) {
        
        let key = generateEntriesKey(filename,keySalt);
        let headerOffset = encryption.generateHeaderOffset(filename);
        let entryOffset = encryption.generateEntriesOffset(filename);
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
    try{
        console.log(readEntries(fn,header,filebuf))
    }catch(e){
        //console.log(e)
    }
}
testReadHead()