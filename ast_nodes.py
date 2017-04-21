from meta import BaseMeta


class Void(object):
    def __init__(self, value):
        self.value = value


class Not(Void):
    pass


class Rule(Void):
    pass


class IfDef(Void):
    pass


class YipNode(BaseMeta):
    pass


class DictNode(YipNode, dict):
    def __init__(self, it=None, *a, **kw):
        if isinstance(it, DictNode):
            self.meta = it.meta
        else:
            self.meta = None
            if it is None:
                a = tuple()
            else:
                a = [it] + list(a)
        dict.__init__(self, *a, **kw)


class ListNode(YipNode, list):
    def __init__(self, *a, **kw):
        self.meta = None
        list.__init__(self, *a, **kw)


class StrNode(YipNode, str):
    def __str__(self):
        return self

    def __new__(cls, v):
        o = str.__new__(cls, v)
        o.meta = None
        return o
