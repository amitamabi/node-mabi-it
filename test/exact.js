const exact = require("../built/exact")
const common = require("../built/common")
const assert = require("assert/strict")
const fs = require("fs")


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
function testExactFile() {
    let buf = new Uint8Array(fs.readFileSync("../mabitdown/download/package/data_00000.it"))
    let exacted = exact.exactFilesFromBuffer("data_00000.it", buf)
    //exacted.map(e => {console.log(e)})
    console.log(exacted)
    // fs.writeFileSync("./s.json",JSON.stringify(exacted,(thi,e)=>{
    //     if(e.constructor === Uint8Array){
    //         //return base64
    //         return bytesArrToBase64(e)
    //     }else {return e}
    // }))
}
testExactFile()