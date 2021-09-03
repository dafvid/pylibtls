from ctypes import Structure, POINTER


class tls(Structure):
    _fields_ = []


tls_p = POINTER(tls)
tls_pp = POINTER(tls_p)


class tls_config(Structure):
    _fields_ = []


tls_config_p = POINTER(tls_config)
