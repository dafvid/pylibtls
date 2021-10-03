import socket

from tls import *
from tls.lib import types, constants


def test_tls_config():
    assert tls_init() == 0
    cfg = tls_config_new()
    assert type(cfg) is types.tls_config_p
    err = tls_config_error(cfg)
    assert err is None

    protocols = tls_config_parse_protocols('secure,!tlsv1.3')
    assert protocols == constants.TLS_PROTOCOL_TLSv1_2
    protocols = tls_config_parse_protocols('secure')
    assert protocols == constants.TLS_PROTOCOL_TLSv1_2 | constants.TLS_PROTOCOL_TLSv1_3

    tls_config_clear_keys(cfg)
    tls_config_free(cfg)


def test_external_server():
    cfg = tls_config_new()
    tls_config_set_ca_file(cfg, "/etc/ssl/cert.pem")
    print(tls_default_ca_cert_file())
    ctx = tls_client()
    tls_configure(ctx, cfg)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = 'www.dafnet.se'
    s.connect((host, 443))
    tls_connect_socket(ctx, s, host)
    tls_handshake(ctx)
    query = "HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n".format(host)
    r = tls_write(ctx, query.encode())
    r = tls_read(ctx)
    print(r.decode())

    tls_config_free(cfg)
    tls_close(ctx)
    tls_free(ctx)
    s.close()


