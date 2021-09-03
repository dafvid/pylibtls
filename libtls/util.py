__all__ = ('Client', 'Server')


class Session:
    def __init__(self):
        self._socket = None


class Client(Session):
    pass


class Server(Session):
    pass
