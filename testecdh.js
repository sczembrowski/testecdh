const crypto = require('crypto');

const ba = crypto.createECDH('prime256v1');
const browser = crypto.createECDH('prime256v1');
const algorithm = 'aes-192-cbc';
baPublicKey = null;
baPrivateKey = null;
browserPublicKey = null
browserPrivateKey = null
step = 1
const start = performance.now();

function logStep(str) {
    const end = performance.now();
    console.log(`${step}. (${end - start} ms) ${str}`);
    step+=1
}


function baDecryptPass(sharedSecret, pass, iv) {

    const key = crypto.scryptSync(sharedSecret, 'salt', 24);

    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(pass, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    logStep(`BA odszyfrowuje hasło (${pass}) ==> (${decrypted})`)
}


function baReceivePass(pass, pubKey, iv) {
    baSharedSecret = ba.computeSecret(pubKey, 'hex', 'hex')
    logStep(`BA odbiera zaszyfrowane hasło, klucz publiczny (${pubKey}) i IV`)
    logStep(`BA wyznaczas shared secred: ${baSharedSecret}`)
    baDecryptPass(baSharedSecret, pass, iv);
}



function browserEncryptPass(sharedSecret, publicKey) {
    //przeglądarka szyfruje hasło użytkownika
    const userPassowrd = "hasło_plain_text";
    let encrypted = '';
    crypto.scrypt(sharedSecret, 'salt', 24, (err, key) => {
        if (err) throw err;
        crypto.randomFill(new Uint8Array(16), (err, iv) => {
            if (err) throw err;

            const cipher = crypto.createCipheriv(algorithm, key, iv);
            cipher.setEncoding('hex');

            cipher.on('data', (chunk) => encrypted += chunk);
            cipher.on('end', () => {
                logStep(`Przeglądarka szyfruje hasło (${userPassowrd})==> ${encrypted}`);
                logStep(`Przeglądarka wysyła zaszyfrowane hasło, klucz publiczny, IV do BA`);
                baReceivePass(encrypted, publicKey, iv);
            });

            cipher.write(userPassowrd);
            cipher.end();
        });
    });
}


function browserReceivesKey(receivedPublic) {
    logStep(`Przeglądarka orbiera klucz publiczny dla konta: ${receivedPublic}`)
    logStep(`Przeglądarka generuje/odczytuje klucze`)
    //przeglądarka generuje (lub odczytuje z lokalnej bazy) klucze
    browser.generateKeys()
    browserPublicKey = browser.getPublicKey('hex')
    browserPrivateKey = browser.getPrivateKey('hex')

    //przeglądarka wyznacza "shared secret"

    browserSharedSecret = browser.computeSecret(receivedPublic, 'hex', 'hex')
    logStep(`Przeglądarka wyznacza shared secret: ${browserSharedSecret}`)
    browserEncryptPass(browserSharedSecret, browserPublicKey);
}


function baCreatesKeys() {

    logStep(`BA generuje/odczytuje klucze dla konta`)
    ba.generateKeys()
    baPublicKey = ba.getPublicKey('hex')
    baPrivateKey = ba.getPrivateKey('hex')
    logStep(`BA przekazje klucz publiczny konta`)
    browserReceivesKey(baPublicKey);
}




baCreatesKeys()


