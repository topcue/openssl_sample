# openssl sample code and 

## install openssl

```
//  Download openssl using a web browser
tar -xzvf openssl-x.x.x.tar.gz
```

```
cd ./openssl-*
./config
make
make test
sudo make install
```
```
sudo ln -s /usr/local/lib/libcrypto.so.1.1 /usr/lib/libcrypto.so
sudo ln -s /usr/local/lib/libssl.so.1.1 /usr/lib/libssl.so
sudo ln -s /usr/local/lib/libcrypto.so.1.1 /usr/lib/libcrypto.so.1.1
sudo ln -s /usr/local/lib/libssl.so.1.1 /usr/lib/libssl.so.1.1
```
```
openssl version
```

aestest
randtest
hmactest
hybrid_cryptosystem
rsaestest
