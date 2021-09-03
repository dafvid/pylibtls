import sys

from ctypes import CDLL, c_int, c_char_p, c_void_p, c_size_t, c_ssize_t

from . import types
from . import constants
from . import errors


_lib = CDLL('/usr/local/lib/libtls.so')


tls_init = _lib.tls_init
tls_init.restype = c_int

tls_config_error = _lib.tls_config_error
tls_config_error.argtypes = [types.tls_config_p]
tls_config_error.restype = c_char_p

tls_error = _lib.tls_error
tls_error.argtypes = [types.tls_p]
tls_error.restype = c_char_p

tls_config_new = _lib.tls_config_new
tls_config_new.restype = types.tls_config_p

tls_config_free = _lib.tls_config_free
tls_config_free.argtypes = [types.tls_config_p]

tls_config_set_ca_file = _lib.tls_config_set_ca_file
tls_config_set_ca_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_ca_file.restype = c_int

tls_config_set_cert_file = _lib.tls_config_set_cert_file
tls_config_set_cert_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_cert_file.restype = c_int

tls_config_set_key_file = _lib.tls_config_set_key_file
tls_config_set_key_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_key_file.restype = c_int

tls_server = _lib.tls_server
tls_server.restype = types.tls_p

tls_client = _lib.tls_client
tls_client.restype = types.tls_p

tls_configure = _lib.tls_configure
tls_configure.argtypes = [types.tls_p, types.tls_config_p]
tls_configure.restype = c_int

tls_reset = _lib.tls_reset
tls_reset.argtypes = [types.tls_p]

tls_free = _lib.tls_free
tls_free.argtypes = [types.tls_p]

tls_accept_socket = _lib.tls_accept_socket
tls_accept_socket.argtypes = [types.tls_p, types.tls_pp, c_int]
tls_accept_socket.restype = c_int

tls_connect_socket = _lib.tls_connect_socket
tls_connect_socket.argtypes = [types.tls_p, types.tls_pp, c_int]
tls_connect_socket.restype = c_int

tls_handshake = _lib.tls_handshake
tls_handshake.argtypes = [types.tls_p]
tls_handshake.restype = c_int

tls_read = _lib.tls_read
tls_read.argtypes = [types.tls_p, c_void_p, c_size_t]
tls_read.restype = c_ssize_t

tls_write = _lib.tls_write
tls_write.argtypes = [types.tls_p, c_void_p, c_size_t]
tls_write.restype = c_ssize_t

tls_close = _lib.tls_close
tls_close.argtypes = [types.tls_p]

__all__ = sorted(name for name in sys.modules[__name__].__dict__ if name.startswith('tls_'))
__all__.extend(('types', 'constants', 'errors'))
