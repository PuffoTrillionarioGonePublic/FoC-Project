- *mykey.pem*: a private key generated with `openssl genrsa -out key.pem 2048`
- *mykey.pub*: a public key generated with `openssl rsa -in mykey.pem -pubout > mykey.pub`
- *mykeypwd.pem*: a password protected public key generated with `openssl genrsa –aes128 -out rsa_privkey.pem 2048`
- *rootCA.pem*: a private key
- *rootca.com.crt*: a certificate generate with `openssl req -x509 -new -nodes -sha256 -key rootCA.pem -subj "/C=IT/ST=XX/O=rootCA/CN=rootca.com" -days 1024 -out rootca.com.crt` (self signed with `rootCA.pem`)
(to print a certificate `openssl x509 -in <certificate>.crt -text`)
- *puffotrillionario.pem*: a private key
- *s3.puffotrillionario.com.csr*: a certificate signing request generated with `openssl req -new -sha256 -key puffotrillionario.pem -subj "/C=IT/ST=XX/O=PuffoTrillionario/CN=s3.puffotrillionario.com" -out s3.puffotrillionario.com.csr` and signed with rootCA with `openssl x509 -req -in s3.puffotrillionario.com.csr -CA rootca.com.crt -CAkey rootCA.pem -CAcreateserial -out s3.puffotrillionario.com.crt -days 500 -sha256`
