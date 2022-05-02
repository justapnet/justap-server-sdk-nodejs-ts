// tslint:disable
import crypto from 'crypto';
import buffer from 'buffer';
import fs from 'fs';

const characters ='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const generateString = function (length) {
    let result = ' ';
    const charactersLength = characters.length;
    for ( let i = 0; i < length; i++ ) {
        result += characters.charAt(Math.floor(Math.random() * charactersLength));
    }

    return result;
}

export function getSign(configuration, localVarFetchArgs: Object) {
    const requestTime = new Date().getTime();
    const nonceStr = generateString(32);
    const bodyStr = localVarFetchArgs.body

    const bodyHash = `${bodyStr}${requestTime}${nonceStr}`;
    const md5 = crypto.createHash('md5');
    const result = md5.update(bodyHash).digest('hex');

    const privateKey = fs.readFileSync(configuration.privateKeyPath, 'utf-8')

    const dataToBeSign = `${bodyHash}${nonceStr}`
    const data = buffer.from(dataToBeSign);
    const signer = crypto.sign("SHA256", data , privateKey);
    const signature = signer.toString("base64");

    localVarFetchArgs.headers = Object.assign({}, localVarFetchArgs.headers, {
        'X-Justap-Signature': signature,
        'X-Justap-Request-Time': requestTime,
        'X-Justap-Nonce': nonceStr,
        'X-Justap-Body-Hash': result,
    });

    return localVarFetchArgs
}