from tls import *
from tls.lib import types


def test_tls_init():
    assert tls_init() == 0


def test_tls_config_new():
    cfg = tls_config_new()
    assert type(cfg) is types.tls_config_p
    err = tls_config_error(cfg)
    assert err is None


def test_tls_config_free():
    cfg = tls_config_new()
    tls_config_free(cfg)


def test_external_server():
    cfg = tls_config_new()

