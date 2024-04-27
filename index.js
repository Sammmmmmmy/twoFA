const crypto = require('crypto');
const base32Decode = require('base32-decode')
// 生成HMAC-based One-Time Password (HOTP)
function generateHOTP(key, counter, digits = 6) {
    // 将计数器转换为8字节的Buffer
    const counterBuffer = Buffer.alloc(8);
    counterBuffer.writeBigInt64BE(BigInt(counter), 0);

    // 使用HMAC-SHA1算法计算HMAC
    const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();

    // 获取HMAC的最后一个字节的低四位作为偏移量
    const offset = hmac[hmac.length - 1] & 0x0F;

    // 将动态密码的部分转换为整数
    let dynamicPassword = (hmac[offset] & 0x7F)<< 24 
      | (hmac[offset + 1] & 0xFF) << 16
      | (hmac[offset + 2] & 0xFF) << 8
      | (hmac[offset + 3] & 0xFF);

    // 限制密码长度
    dynamicPassword = dynamicPassword % Math.pow(10, digits);

    // 根据指定的位数格式化密码
    return dynamicPassword.toString().padStart(digits, '0');
}

// 获取当前时间的时间戳，并以时间步长划分为计数器
function getCounter(timeStep = 30) {
    const currentTime = Math.floor(Date.now() / 1000); // 获取当前时间戳（单位：秒）
    return Math.floor(currentTime / timeStep);
}

// 生成 TOTP
function generateTOTP(key, timeStep = 30, digits = 6) {
    const counter = getCounter(timeStep);
    console.log(counter)
    return generateHOTP(key, counter, digits);
}

// 示例
const secret = 'Github 2FA认证提供的经过base32（RFC3548）编码后的secretKey'; // 这是你的秘钥，需要保密
const secretKey = Buffer.from(base32Decode(secret, 'RFC3548'));
const totp = generateTOTP(secretKey);
console.log('Generated TOTP:', totp);
