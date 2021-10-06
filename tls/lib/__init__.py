import sys

from ctypes import POINTER, CDLL, c_int, c_char_p, c_void_p, c_size_t, c_ssize_t, c_uint32

from . import types

# TODO load by name or env
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

tls_default_ca_cert_file = _lib.tls_default_ca_cert_file
tls_default_ca_cert_file.restype = c_char_p

tls_config_add_keypair_file = _lib.tls_config_add_keypair_file
tls_config_add_keypair_file.argtypes = [types.tls_config_p, c_char_p, c_char_p]
tls_config_add_keypair_file.restype = c_int

tls_config_add_keypair_ocsp_file = _lib.tls_config_add_keypair_ocsp_file
tls_config_add_keypair_ocsp_file.argtypes = [types.tls_config_p, c_char_p, c_char_p, c_char_p]
tls_config_add_keypair_ocsp_file.restype = c_int

tls_config_set_alpn = _lib.tls_config_set_alpn
tls_config_set_alpn.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_alpn.restype = c_int

tls_config_set_ca_file = _lib.tls_config_set_ca_file
tls_config_set_ca_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_ca_file.restype = c_int

tls_config_set_ca_path = _lib.tls_config_set_ca_path
tls_config_set_ca_path.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_ca_path.restype = c_int

tls_config_set_cert_file = _lib.tls_config_set_cert_file
tls_config_set_cert_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_cert_file.restype = c_int

tls_config_set_ciphers = _lib.tls_config_set_ciphers
tls_config_set_ciphers.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_ciphers.restype = c_int

tls_config_set_crl_file = _lib.tls_config_set_crl_file
tls_config_set_crl_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_crl_file.restype = c_int

tls_config_set_dheparams = _lib.tls_config_set_dheparams
tls_config_set_dheparams.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_dheparams.restype = c_int

tls_config_set_ecdhecurves = _lib.tls_config_set_ecdhecurves
tls_config_set_ecdhecurves.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_ecdhecurves.restype = c_int

tls_config_set_key_file = _lib.tls_config_set_key_file
tls_config_set_key_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_key_file.restype = c_int

tls_config_set_keypair_file = _lib.tls_config_set_keypair_file
tls_config_set_keypair_file.argtypes = [types.tls_config_p, c_char_p, c_char_p]
tls_config_set_keypair_file.restype = c_int

tls_config_set_keypair_ocsp_file = _lib.tls_config_set_keypair_ocsp_file
tls_config_set_keypair_ocsp_file.argtypes = [types.tls_config_p, c_char_p, c_char_p, c_char_p]
tls_config_set_keypair_ocsp_file.restype = c_int

tls_config_set_ocsp_staple_file = _lib.tls_config_set_ocsp_staple_file
tls_config_set_ocsp_staple_file.argtypes = [types.tls_config_p, c_char_p]
tls_config_set_ocsp_staple_file.restype = c_int

tls_config_set_protocols = _lib.tls_config_set_protocols
tls_config_set_protocols.argtypes = [types.tls_config_p, c_uint32]
tls_config_set_protocols.restype = c_int

tls_config_set_session_fd = _lib.tls_config_set_session_fd
tls_config_set_session_fd.argtypes = [types.tls_config_p, c_int]
tls_config_set_session_fd.restype = c_int

tls_config_set_verify_depth = _lib.tls_config_set_verify_depth
tls_config_set_verify_depth.argtypes = [types.tls_config_p, c_int]
tls_config_set_verify_depth.restype = c_int

tls_config_prefer_ciphers_client = _lib.tls_config_prefer_ciphers_client
tls_config_prefer_ciphers_client.argtypes = [types.tls_config_p]

tls_config_prefer_ciphers_server = _lib.tls_config_prefer_ciphers_server
tls_config_prefer_ciphers_server.argtypes = [types.tls_config_p]

tls_config_insecure_noverifycert = _lib.tls_config_insecure_noverifycert
tls_config_insecure_noverifycert.argtypes = [types.tls_config_p]

tls_config_insecure_noverifyname = _lib.tls_config_insecure_noverifyname
tls_config_insecure_noverifyname.argtypes = [types.tls_config_p]

tls_config_insecure_noverifytime = _lib.tls_config_insecure_noverifytime
tls_config_insecure_noverifytime.argtypes = [types.tls_config_p]

tls_config_verify = _lib.tls_config_verify
tls_config_verify.argtypes = [types.tls_config_p]

tls_config_ocsp_require_stapling = _lib.tls_config_ocsp_require_stapling
tls_config_ocsp_require_stapling.argtypes = [types.tls_config_p]

tls_config_verify_client = _lib.tls_config_verify_client
tls_config_verify_client.argtypes = [types.tls_config_p]

tls_config_verify_client_optional = _lib.tls_config_verify_client_optional
tls_config_verify_client_optional.argtypes = [types.tls_config_p]

tls_config_clear_keys = _lib.tls_config_clear_keys
tls_config_clear_keys.argtypes = [types.tls_config_p]

tls_config_parse_protocols = _lib.tls_config_parse_protocols
tls_config_parse_protocols.argtypes = [POINTER(c_uint32), c_char_p]
tls_config_parse_protocols.restype = c_int

tls_client = _lib.tls_client
tls_client.restype = types.tls_p

tls_server = _lib.tls_server
tls_server.restype = types.tls_p

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

tls_connect = _lib.tls_connect
tls_connect.argtypes = [types.tls_p, c_char_p, c_char_p]
tls_connect.restype = c_int

tls_connect_servername = _lib.tls_connect_servername
tls_connect_servername.argtypes = [types.tls_p, c_char_p, c_char_p, c_char_p]
tls_connect_servername.restype = c_int

tls_connect_socket = _lib.tls_connect_socket
tls_connect_socket.argtypes = [types.tls_p, c_int, c_char_p]
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
tls_close.restype = c_int

tls_peer_cert_provided = _lib.tls_peer_cert_provided
tls_peer_cert_provided.argtypes = [types.tls_p]
tls_peer_cert_provided.restypes = c_int

tls_peer_cert_contains_name = _lib.tls_peer_cert_contains_name
tls_peer_cert_contains_name.argtypes = [types.tls_p, c_char_p]
tls_peer_cert_contains_name.restype = c_int

tls_peer_cert_hash = _lib.tls_peer_cert_hash
tls_peer_cert_hash.argtypes = [types.tls_p]
tls_peer_cert_hash.restype = c_char_p

tls_peer_cert_issuer = _lib.tls_peer_cert_issuer
tls_peer_cert_issuer.argtypes = [types.tls_p]
tls_peer_cert_issuer.restype = c_char_p

tls_peer_cert_subject = _lib.tls_peer_cert_subject
tls_peer_cert_subject.argtypes = [types.tls_p]
tls_peer_cert_subject.restype = c_char_p

tls_peer_cert_notbefore = _lib.tls_peer_cert_notbefore
tls_peer_cert_notbefore.argtypes = [types.tls_p]
tls_peer_cert_notbefore.restype = types.time_t

tls_peer_cert_notafter = _lib.tls_peer_cert_notafter
tls_peer_cert_notafter.argtypes = [types.tls_p]
tls_peer_cert_notafter.restype = types.time_t

tls_conn_alpn_selected = _lib.tls_conn_alpn_selected
tls_conn_alpn_selected.argtypes = [types.tls_p]
tls_conn_alpn_selected.restype = c_char_p

tls_conn_cipher = _lib.tls_conn_cipher
tls_conn_cipher.argtypes = [types.tls_p]
tls_conn_cipher.restype = c_char_p

tls_conn_cipher_strength = _lib.tls_conn_cipher_strength
tls_conn_cipher_strength.argtypes = [types.tls_p]
tls_conn_cipher_strength.restype = c_int

tls_conn_servername = _lib.tls_conn_servername
tls_conn_servername.argtypes = [types.tls_p]
tls_conn_servername.restype = c_char_p

tls_conn_session_resumed = _lib.tls_conn_session_resumed
tls_conn_session_resumed.argtypes = [types.tls_p]
tls_conn_session_resumed.restype = c_int

tls_conn_version = _lib.tls_conn_version
tls_conn_version.argtypes = [types.tls_p]
tls_conn_version.restype = c_char_p

tls_ocsp_process_response = _lib.tls_ocsp_process_response
tls_ocsp_process_response.argtypes = [types.tls_p, c_char_p, c_size_t]
tls_ocsp_process_response.restype = c_int

tls_peer_ocsp_cert_status = _lib.tls_peer_ocsp_cert_status
tls_peer_ocsp_cert_status.argtypes = [types.tls_p]
tls_peer_ocsp_cert_status.restype = c_int

tls_peer_ocsp_crl_reason = _lib.tls_peer_ocsp_crl_reason
tls_peer_ocsp_crl_reason.argtypes = [types.tls_p]
tls_peer_ocsp_crl_reason.restype = c_int

tls_peer_ocsp_next_update = _lib.tls_peer_ocsp_next_update
tls_peer_ocsp_next_update.argtypes = [types.tls_p]
tls_peer_ocsp_next_update.restype = types.time_t

tls_peer_ocsp_response_status = _lib.tls_peer_ocsp_response_status
tls_peer_ocsp_response_status.argtypes = [types.tls_p]
tls_peer_ocsp_response_status.restype = c_int

tls_peer_ocsp_result = _lib.tls_peer_ocsp_result
tls_peer_ocsp_result.argtypes = [types.tls_p]
tls_peer_ocsp_result.restype = c_char_p

tls_peer_ocsp_revocation_time = _lib.tls_peer_ocsp_revocation_time
tls_peer_ocsp_revocation_time.argtypes = [types.tls_p]
tls_peer_ocsp_revocation_time.restype = types.time_t

tls_peer_ocsp_this_update = _lib.tls_peer_ocsp_this_update
tls_peer_ocsp_this_update.argtypes = [types.tls_p]
tls_peer_ocsp_this_update.restype = types.time_t

tls_peer_ocsp_url = _lib.tls_peer_ocsp_url
tls_peer_ocsp_url.argtypes = [types.tls_p]
tls_peer_ocsp_url.restype = c_char_p

__all__ = sorted(name for name in sys.modules[__name__].__dict__ if name.startswith('tls_'))
__all__.extend(('types', 'constants', 'errors'))
