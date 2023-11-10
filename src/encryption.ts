/**
 * @module
 */
const KEY_SALT = "@6QeTuOaDgJlZcBm#9"
import SnowCipher = require("snow2cipher")
import {Buffer} from "buffer"

/**
 * Genreate Offset to Decrypt .it File Header.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {number} This is Genreated Offset;
 */
export function generateHeaderOffset(name:string):number {
	const input = new Uint16Array(name.toLowerCase().split("").map(c=>c.charCodeAt(0)))
	const sum = input.reduce((pv,cv,ci)=>{
		return pv + cv
	},0)
	return sum % 312 + 30
}

/**
 * Genreate Key to Decrypt .it File Header.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {Uint8Array} This is Genreated Key;
 */
export function generateHeaderKey(name:string,keySalt:string = KEY_SALT):Uint8Array{
	let input = new Uint16Array((name.toLowerCase()+keySalt).split("").map(c=>c.charCodeAt(0)))
	let key = new Uint8Array(16);
	for (let i = 0; i < 16; i++) {
		key[i] = input[i%input.length] + i;
	}
	return key
}

/**
 * Genreate Key to Decrypt .it File Entries.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {Uint8Array} This is Genreated Key;
 */
export function generateEntriesKey(name:string,keySalt:string = KEY_SALT):Uint8Array{
	let input = new Uint16Array((name.toLowerCase()+keySalt).split("").map(c=>c.charCodeAt(0)))
	let key = new Uint8Array(16);
	let len = input.length
	for (let i = 0; i < 16; i++) {
		key[i] = (i + (i%3+2) * input[len - 1 - i % len]) %256
	}
	return key
}
/**
 * Genreate Offset to Decrypt .it File Entries.
 * @param {string}name - Just input the *.it file's filename;
 * @returns {number} This is Genreated Offset;
 */
export function generateEntriesOffset(name:string):number{
	const input = new Uint16Array(name.toLowerCase().split("").map(c=>c.charCodeAt(0)))
	const r = input.reduce((pv,cv,ci)=>{
		return pv + (cv *3)
	},0)
	return r % 212 + 42
}

export function generateFileKey(name:string,key2:Uint8Array):Uint8Array{
	let input = new Uint16Array(name.split("").map(c=>c.charCodeAt(0)))
	let key = new Uint8Array(16);
	if(key2.length !== 16){
		throw new Error("key2 must be 16 bytes")
	}
	//IDK IT'S WORKABLE.
	for (let i = 0; i < 16; i++) {
		//默认浮点 害人不浅 这段已经浪费至少我四个小时去调。
		// use >>>0 to convert to int.
		key[i] = input[i % input.length] * (key2[i % 16] - (i/5>>>0)*5 + 2 + i) + i
	}
	return key
}

/**
 * Decrypt Data From Buffer
 * @param {Uint8Array|Buffer}buf - Buffer to Decrypt;
 * @param {Uint8Array}key - Key to Decrypt, MUST LENGTH == 16;
 * @returns {Uint8Array} This is Decrypted Data;
 */
export function decryptDataFromBuffer(buf:(Uint8Array|Buffer),key:Uint8Array):Uint8Array{
	//key uint8array
	//buf uint32array,LE
	//return uint8array
	let copiedKey = Uint8Array.prototype.slice.call(key)
	let s8key = new Int8Array(copiedKey.buffer)//Weird Mabinogi Cihper Call.
	let cipher = new SnowCipher({
		key:s8key,
		keySize:128,
		ivTable:new Uint32Array([0x0,0x0,0x0,0x0]),
	})
	let data
	if(buf.byteLength % 4 != 0){
		throw new Error("buf length must be multiple of 4")
	}else{
		data= new Uint32Array(buf.buffer)
	}
	for(let i=0;i<data.length;i++){
		//Why Mabinogi use add/sub instead of xor? It can't to padding with 0x0. 
		data[i] -= cipher.singleClock()
	}
	return new Uint8Array(data.buffer)
}
/**
 * Encrypt Data From Buffer
 * @param {Uint8Array|Buffer}buf - Buffer to Encrypt;
 * @param {Uint8Array}key - Key to Encrypt, MUST LENGTH == 16;
 * @returns {Uint8Array} This is Encrypted Data;
 */
export function encryptDataFromBuffer(buf:(Uint8Array|Buffer),key:Uint8Array):Uint8Array{
	//key uint8array
	//buf uint32array,LE
	//return uint8array
	let copiedKey = Uint8Array.prototype.slice.call(key)
	let cipher = new SnowCipher({
		key:new Int8Array(copiedKey.buffer),
		keySize:128,
		ivTable:new Uint32Array([0x0,0x0,0x0,0x0]),
	})
	let data
	if(buf.byteLength % 4 != 0){
		throw new Error("buf length must be multiple of 4")
	}else{
		data= new Uint32Array(buf.buffer)
	}
	
	for(let i=0;i<data.length;i++){
		data[i] += cipher.singleClock()
	}
	return new Uint8Array(data.buffer,0,buf.byteLength)
}
module.exports = {
	generateHeaderOffset,
	generateHeaderKey,
	generateEntriesKey,
	generateEntriesOffset,
	generateFileKey,
	decryptDataFromBuffer,
	encryptDataFromBuffer
}

