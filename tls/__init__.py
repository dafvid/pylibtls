from ctypes import create_string_buffer

from . import lib

from .lib.constants import *


class TLSError(Exception):
    pass


def tls_init():
    return lib.tls_init()


def tls_config_error(_config):
    e = lib.tls_config_error(_config)
    if e is not None:
        return e.decode()


def tls_error(_tls):
    e = lib.tls_error(_tls)
    if e is not None:
        return e.decode()


def tls_config_new():
    return lib.tls_config_new()


def tls_config_free(_config):
    lib.tls_config_free(_config)


def tls_default_ca_cert_file():
    ca_cert = lib.tls_default_ca_cert_file()
    if ca_cert is not None:
        return ca_cert.decode()


def tls_config_set_ca_file(_config, _ca_file):
    r = lib.tls_config_set_ca_file(_config, _ca_file.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))


def tls_config_set_ca_path(_config, _ca_path):
    r = lib.tls_config_set_ca_path(_config, _ca_path.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_cert_file(_config, _cert_file):
    r = lib.tls_config_set_cert_file(_config, _cert_file.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_ciphers(_config, _ciphers):
    r = lib.tls_config_set_ciphers(_config, _ciphers.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_crl_file(_config, _crl_file):
    r = lib.tls_config_set_crl_file(_config, _crl_file.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_dheparams(_config, _params):
    r = lib.tls_config_set_dheparams(_config, _params.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_ecdhecurve(_config, _curve):
    r = lib.tls_config_set_ecdhecurve(_config, _curve.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_ecdhecurves(_config, _curves):
    r = lib.tls_config_set_ecdhecurves(_config, _curves.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_key_file(_config, _key_file):
    r = lib.tls_config_set_key_file(_config, _key_file.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))


def tls_config_set_ocsp_staple_file(_config, _staple_file):
    r = lib.tls_config_set_ocsp_staple_file(_config, _staple_file.encode())
    if r == -1:
        raise TLSError(tls_config_error(_config))
    

def tls_config_set_protocols(_config, _protocols):
    r = lib.tls_config_set_protocols(_config, _protocols)
    if r == -1:
        raise TLSError(tls_config_error(_config))


def tls_config_set_session_fd(_config, _session_fd):
    r = lib.tls_config_set_session_fd(_config, _session_fd)
    if r == -1:
        raise TLSError(tls_config_error(_config))

    
def tls_config_set_verify_depth(_config, _verify_depth):
    r = lib.tls_config_set_verify_depth(_config, _verify_depth)
    if r == -1:
        raise TLSError(tls_config_error(_config))


def tls_server():
    return lib.tls_server()


def tls_client():
    return lib.tls_client()


def tls_configure(_ctx, _config):
    r = lib.tls_configure(_ctx, _config)
    if r == -1:
        raise TLSError(tls_error(_ctx))


def tls_reset(_ctx):
    lib.tls_reset(_ctx)


def tls_free(_ctx):
    lib.tls_free(_ctx)


def tls_accept_socket(_ctx, _cctx, _socket):
    r = lib.tls_accept_socket(_ctx, _cctx, _socket.fileno())
    if r == -1:
        raise TLSError(tls_error(_ctx))


def tls_connect_socket(_ctx, _s, _servername):
    r = lib.tls_connect_socket(_ctx, _s.fileno(), _servername.encode())
    if r == -1:
        raise TLSError(tls_error(_ctx))


def tls_handshake(_ctx):
    r = lib.tls_handshake(_ctx)
    if r == -1:
        raise TLSError(tls_error(_ctx))


def tls_read(_ctx, _buflen):
    _buf = create_string_buffer(_buflen)
    r = lib.tls_read(_ctx, _buf, _buflen)
    if r == -1:
        raise TLSError(tls_error(_ctx))
    return _buf.value


def tls_write(_ctx, _data):
    _buflen = len(_data)
    r = lib.tls_write(_ctx, _data, _buflen)
    if r == -1:
        raise TLSError(tls_error(_ctx))
    return r
