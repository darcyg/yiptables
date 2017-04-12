import re
from collections import ChainMap

simple_format = re.compile('^{[^}]+}$')


def yip_stringize(e):
    if not any(map(lambda x: isinstance(e, x), (int, str))):
        raise SyntaxError(f'Element is not a string: {e}')
    return str(e)


def yip_str_format(scope, string):
    if re.match(simple_format, string):
        lookup_res = scope.get(string[1:-1])
        return lookup_res if lookup_res is not None else string
    return string.format(**scope)


def yip_dict_format(scope, d):
    return {k: yip_format(scope, v) for k, v in d.items()}


def yip_list_format(scope, d):
    return [yip_format(scope, v) for v in d]


def yip_format(scope, e):
    if isinstance(e, dict):
        return yip_dict_format(scope, e)
    elif isinstance(e, list):
        return yip_list_format(scope, e)
    elif isinstance(e, str):
        return yip_str_format(scope, e)
    return yip_stringize(e)


def yip_ld_iter(ld):
    if isinstance(ld, list):
        for e in ld:
            yield from yip_ld_iter(e)
    elif isinstance(ld, dict):
        yield from ld.items()
    else:
        raise SyntaxError(f'Cannot iterate as dict on: {ld}')


def yip_flatten_iter(l):
    if isinstance(l, list):
        for e in l:
            yield from yip_flatten_iter(e)
    else:
        yield l


class Scope(ChainMap):
    def sub_scope(self, local=None):
        return self.new_child(local)


class VarScope(Scope):
    def get_vars(self, node, attr='vars'):
        if attr is not None:
            node = node.get(attr)
            if node is None:
                return
        print(f'node: {node}')
        for k, v in yip_ld_iter(node):
            print(f'int::{k}: {v}')
            self[k] = yip_format(self, v)


class Registrator():
    def __init__(self, fmap):
        self.fmap = fmap

    def __call__(self, *fnames):
        def assign(f):
            for fname in fnames:
                if fname in self.fmap:
                    raise SyntaxError(
                        f'feature token `{fname}` was'
                        f'used multiple times'
                    )
                self.fmap[fname] = f
            return f
        return assign
