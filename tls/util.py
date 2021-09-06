import time

from . import tls_write, tls_read


def sendall(ctx, data):
    size = len(data)
    while size > 0:
        sent = tls_write(ctx, data)
        size -= sent
        data = data[sent:]


def readall(ctx, timeout=2, bufsize=2048):
    data = list()
    ts = time.time()
    waiting = False

    while True:
        if time.time() - ts > timeout:
            break

        frag = tls_read(ctx, bufsize)
        if frag:
            data.append(frag)
            waiting = False
        else:
            if waiting:
                break
            time.sleep(0.1)
            waiting = True

    return b''.join(data)
