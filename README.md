# pylibtls
[![PyPI version](https://badge.fury.io/py/pylibtls.svg)](https://badge.fury.io/py/pylibtls)

## About
Developed initially in september 2021 on FreeBSD 13.0 with LibreSSL 3.3.3 with API Version `20200120`. 

The aim is to just wrap the API as thinly as possible. A few principles: 
- `str` is encoded using default encoding (just calling `encode()`)
- Epochs are converted to UTC datetime
- Return code `-1` is made into `TLSError`
- Returned `1`s and `0`s are cast to `boolean`
- Returned strings are converted with `decode()`
- `tls_read()` and `tls_write()` expects `bytes` though
- The order of the functions defined matches that of libtls.h
- Argument names are not always pythonic but matches that of libtls.h

## Background
I always thought it was a bit of a mistake for [LibreSSL](https://www.libressl.org/index.html) to be an drop-in replacement for OpenSSL. I just wanted to use libtls and be done with it. But since LibreSSL always replaced OpenSSL and that always seemed to be problematic I looked for ways to install just libtls, but to no awail. Until April 18, 2021 when version 3.3.2 of LibreSSL was released.

From the [release notes](https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.3.2-relnotes.txt) (way down): 
>Added '--enable-libtls-only' build option, which builds and installs a statically-linked libtls, skipping libcrypto and libssl. This is useful for systems that ship with OpenSSL but wish to also package libtls.

*YEY!*

Some time after it was made a [flavor](https://docs.freebsd.org/en/books/porters-handbook/flavors/) of the FreeBSD LibreSSL [port](https://www.freshports.org/security/libressl/). So now I finally had it! So I started looking for Python wrappers for it. I found [python-libtls](https://pypi.org/project/python-libtls/) by Vinay Sajip. Last update in 2017, looked abandoned, so [I made a new one](https://www.youtube.com/channel/UCMrMVIBtqFW6O0-MWq26gqw).

## Getting started
### Getting libtls
First thing is getting libtls somehow. If you already have LibreSSL you should be good to go. Otherwise hope the **&#x2011;&#x2011;enable&#x2011;libtls&#x2011;only** build flag is used somehow in whatever package thingamajig you're using.
#### FreeBSD
```sh
pkg install libressl-libtls
```
#### MacOS
I was suprised to find out Apple deprecated OpenSSL after High Sierra and now ships with LibreSSL. But you can't use it =/. But install it with Homebrew!
```zsh
brew install libressl
```
It's not linked since it would mess with the one shipped with MacOS. Set the env variable `PYLIBTLS_LIBTLS_PATH` to `/usr/local/opt/libressl/lib/libtls.dylib` and you're good to go.

#### Linux (Rocky Linux 8.4)
There's no love for libtls in the Linux community! So no package in rpm. Beware of the package `libretls`, it's libtls on top of OpenSSL!
But thankfully it's pretty easy to compile it yourself. This is how I installed it on Rocky Linux, YMMW. Instructions @ [GitHub](https://github.com/libressl-portable/portable)
```sh
dnf install wget
wget https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-3.3.5.tar.gz
cd libressl-3.3.5
./configure --enable-libtls-only  # very important flag!
make check  # as recommended on GitHub
make install
```
Now it's installed in `/usr/local/lib` but you need to tell the linker that. There's a few ways to do that. I added the path to `/etc/ld.so.con`. You can also add it to env var `LD_LIBRARY_PATH`.

Then you need to tell libtls how to find your CA bundle. The default path is apparently hard coded to `/etc/ssl/cert.pem`. This is NOT where Rocky Linux keeps them, so I soft linked it like so:
```sh
ln -s /etc/pki/tls/cert.pem /etc/ssl/cert.pem
```
This all depends on your distro. All RHEL derivaties keep their bundle in `/etc/pki/tls/cert.pem`.

#### Environment variables
There's an env variable you can use to specify the path to libtls if `ctypes` is unable to find it automagically and that's `PYLIBTLS_LIBTLS_PATH`.

### Getting pylibtls
Just use pip:
```sh
$> pip install pylibtls
```
and in your script
```py
import tls
```

## Usage
Oh the fun part!

Functions are named the same so `tls_init()` is `tls.tls_init()` and so on. Constants from header file are just `tls.TLS_A_CONSTANT`.

```python
from tls import (tls_config_new, tls_client, tls_configure, tls_connect, tls_write, 
                tls_read, tls_config_free, tls_close, tls_free)

cfg = tls_config_new()
ctx = tls_client()
tls_configure(ctx, cfg)

host = 'www.openbsd.org'
tls_connect(ctx, host, 443)
query = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host)
tls_write(ctx, query.encode())
r = tls_read(ctx)
print(r.decode())

tls_config_free(cfg)
tls_close(ctx)
tls_free(ctx)
```

The full monty

```python
from tls import *

print('Version:', TLS_API)
cfg = tls_config_new()
tls_config_set_ca_file(cfg, "/etc/ssl/cert.pem")
print(tls_default_ca_cert_file())
tls_config_set_protocols(cfg, TLS_PROTOCOL_TLSv1_2)
ctx = tls_client()
tls_configure(ctx, cfg)

host = 'www.openbsd.org'
print('host:', host)

print('connect_socket')
tls_connect(ctx, host, 443)
tls_handshake(ctx)
print("Cert provided:", tls_peer_cert_provided(ctx))
print("Hash (SHA256):", tls_peer_cert_hash(ctx))
print("Issuer:", tls_peer_cert_issuer(ctx))
print("Subject:", tls_peer_cert_subject(ctx))
print("NotBefore (UTC):", tls_peer_cert_notbefore(ctx))
print("NotAfter (UTC):", tls_peer_cert_notafter(ctx))
print("ALPN:", tls_conn_alpn_selected(ctx))
print("Cipher:", tls_conn_cipher(ctx))
print("Servername:", tls_conn_servername(ctx))
print("Resumed:", tls_conn_session_resumed(ctx))
print("TLS Version:", tls_conn_version(ctx))
print("OCSP URL:", tls_peer_ocsp_url(ctx))
print("OCSP result:", tls_peer_ocsp_result(ctx))
if tls_peer_ocsp_result(ctx) is not None:
    print("OCSP Response Status:", TLS_OCSP_RESPONSE[tls_peer_ocsp_response_status(ctx)])
    print("OCSP Cert Status:", TLS_OCSP_CERT[tls_peer_ocsp_cert_status(ctx)])
    print("OCSP CRL Reason:", TLS_CRL_REASON[tls_peer_ocsp_crl_reason(ctx)])
    print("OCSP revocation:", tls_peer_ocsp_revocation_time(ctx))
    print("OCSP this update:", tls_peer_ocsp_this_update(ctx))
    print("OCSP next update:", tls_peer_ocsp_next_update(ctx))

print()
query = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host)
print('tls_write', query)
r = tls_write(ctx, query.encode())
print(r, 'bytes')
print('read')
r = tls_read(ctx)
print(len(r), 'bytes')
print(r.decode())

tls_config_free(cfg)
tls_close(ctx)
tls_free(ctx)
```
This is using the extra `dict`s I put in for reverse lookup of values-to-name: `TLS_OCSP_RESPONSE`, `TLS_OCSP_CERT` and `TLS_CRL_REASON`. They require that OCSP stapling is active on the server in question. In the example, it is.

Very simple server
```py
from tls import *
import socket


cfg = tls_config_new()
tls_config_set_keypair_file(cfg, 'cert.pem', 'privkey.pem')

ctx = tls_server()
tls_configure(ctx, cfg)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('www.example.com', 2345))
s.listen(10)
print('Listening on socket...')
c, addr = s.accept()
print(addr, 'connected')
cctx = tls_accept_socket(ctx, c)
tls_write(cctx, 'Hello World'.encode())
print(tls_read(cctx))
tls_close(cctx)
tls_free(cctx)

tls_config_free(cfg)
tls_free(ctx)

s.close()
```
Accepts a single connection and writes `Hello World` then reads once and shuts down.

## Documentation
None yet, apart from this README. See the [OpenBSD documentation](https://man.openbsd.org/tls_init.3) for reference. It should get you up and running somewhat.

## Status
#### 2021-10-17
Instructions for Linux (Rocky Linux 8.4)
#### 2021-10-09
Published on [PyPi](https://pypi.org/project/pylibtls/)!
#### 2021-10-08
First pushed to GitHub (A bit nervous). Most of the API implemented. Only client functionality tested. No local OCSP-stuff (getting the staple file is HARD). Only tested on FreeBSD. Should work fine on Linux at least. No `libtls-only` brew Formulae so MacOS is out (might be next project). Windows seems to be a sad chapter in general. Vinay stranded [here](https://github.com/libressl-portable/portable/issues/266) more or less.

## TODO
- [ ] All `mem`-functions that read stuff from memory loaded with `tls_load_file()`
- [ ] Callbacks versions of `tls_accept()` and `tls_connect()`
- [ ] File descriptor versions of the same
- [ ] `tls_peer_cert_chain_pem()`
- [ ] `assert` a few things here and there

## Acknowledgments
- [python-libtls](https://bitbucket.org/vinay.sajip/python-libtls/src/master/) and [python-gnutls](https://github.com/AGProjects/python-gnutls) for inspiration
