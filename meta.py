class Meta():
    def __meta__(self):
        return self

    def __init__(self, f, l, c):
        self.line = l
        self.file = str(f)
        self.col = c

    def __str__(self):
        return f'{self.file}:{self.line}'


class BaseMeta():
    def __meta__(self):
        assert(self.meta is not None)
        return self.meta


def meta(o):
    return o.__meta__()


def hasmeta(o):
    return hasattr(o, '__meta__')


class YipSyntaxError(BaseMeta, Exception):
    def __init__(self, ometa, msg, parent=None):
        super().__init__(msg)
        self.parent = parent
        self.meta = meta(ometa)

    def __str__(self):
        msg = super().__str__()
        return f'{msg}:\n\t{str(self.meta)}'
