const { FileEntry,FileHeader } = require("../built/common")
const encryption = require("../built/encryption")
const {RawFileEntry,exactFilesFromBuffer} = require("../built/exact")
const {packToNewBuffer} = require("../built/pack")

function genetateRawFileEntry(FileEntry,content){
    let entry = new RawFileEntry()
    entry.originalEntry = FileEntry
    entry.content = content
    return entry
}
function pack(){
    //let rawEntries = []
    let filename = "test_data.it"
    let entries = [
        genetateRawFileEntry(FileEntry.fromObject({
            name:"data/color/black.raw",
            offset:0,
            originalSize:4,
            flags:6,
            rawSize:4,
            checksum:0,
            key:new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
        }),new Uint8Array([0,0,0,0])),
        genetateRawFileEntry(FileEntry.fromObject({
            name:"data/color/white.raw",
            offset:0,
            originalSize:4,
            flags:6,
            rawSize:4,
            checksum:0,
            key:new Uint8Array([15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0])
        }),new Uint8Array([255,255,255,255])),
        genetateRawFileEntry(FileEntry.fromObject({
            name:"data/color/ff.raw",
            offset:0,
            originalSize:16,
            flags:7,
            rawSize:4,
            checksum:0,
            key:new Uint8Array([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
        }),new Uint8Array([255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255]))
    ]
    let buf = packToNewBuffer(entries,filename)
    let fileHeader = FileHeader.readEncryptHeader(filename,buf)
    let fileEnt = FileEntry.readEntries(filename,fileHeader,buf)
    console.log(fileEnt)
    let unpacked = exactFilesFromBuffer(filename,buf)
    console.log(unpacked)
}
pack()