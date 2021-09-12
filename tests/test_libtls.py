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

