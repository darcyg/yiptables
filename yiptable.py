import yaml
import os.path
from features import feature_map

from tools import (
    yip_ld_iter,
    yip_flatten_iter,
    yip_dict_format,
    yip_format,
    Scope,
    VarScope,
    Registrator,
)


class YipLoader(yaml.Loader):
    def __init__(self, stream):
        self._root = os.path.split(stream.name)[0]
        super().__init__(stream)

    def include(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, YipLoader)

    @classmethod
    def load(cls, fd):
        return yaml.load(fd, cls)


YipLoader.add_constructor('!import', YipLoader.include)


class Table():
    default_chains = []

    def __init__(self, yip, name):
        self.yip = yip
        self.scope = yip.scope.sub_scope()
        default_chains = yip.chains.sub_scope(
            local={e: None for e in self.default_chains}
        )
        self.local_chains = {}
        self.chains = default_chains.sub_scope(local=self.local_chains)
        self.name = name
        self.rules = []

    def add_chain(self, chain, policy):
        if chain in self.chains:
            raise SyntaxError(f'Redundant target declaration for: {chain}')
        self.chains[chain] = policy

    def add_rule(self, rule_node, scope=None):
        rule = Rule(self)
        rule.build(rule_node)
        self.rules.append(rule)

    def build_chains(self, node):
        assert(isinstance(node, dict))
        for cname, target in yip_dict_format(self.scope, node).items():
            if target not in self.chains:
                raise SyntaxError(f'Unknown target: {target}')
            if cname in self.chains:
                raise SyntaxError(f'Tried to redefine chain: {cname}')
            self.chains[cname] = target

    def build_rules(self, node, scope):
        assert(isinstance(node, list))
        for rule_node in node:
            assert(isinstance(rule_node, dict))
            if 'with_items' in rule_node:
                for item in yip_flatten_iter(rule_node.pop('with_items')):
                    nitem = yip_format(scope, item)
                    if isinstance(nitem, str):
                        nitem = {'item': nitem}
                    assert(isinstance(nitem, dict))
                    self.add_rule(rule_node, Scope(nitem, scope))

            if 'block' in rule_node:
                subrules = rule_node.get('rules')
                if not subrules:
                    raise SyntaxError('block has no rules attribute')
                nscope = VarScope(scope)
                nscope.get_vars(rule_node, attr='block')
                self.build_rules(subrules, nscope)
            else:
                self.add_rule(rule_node)

    def build(self, node):
        chains_node = node.get('chains')
        if chains_node:
            self.build_chains(chains_node)

        rules_node = node.get('rules')
        if rules_node:
            self.build_rules(rules_node, self.scope)

    def render(self):
        chains = '\n'.join(
            f':{c} {pol} [0:0]' for c, pol in self.local_chains.items()
        )
        rules = '\n'.join(r.render() for r in self.rules)
        return f'*{self.name}\n{chains}\n\n{rules}\n\nCOMMIT'


class Rule():
    def __init__(self, table, scope=None, rtype='-A'):
        self.scope = table.scope.sub_scope() if scope is None else scope
        self.table = table
        self.dependencies = set()
        self.targets = []
        self.chain = None
        self.rtype = rtype
        self.has_comment = False

    def build(self, node):
        for fname, val in yip_ld_iter(node):
            if fname not in feature_map:
                print(f'missing feature: {fname}')
                print(f'dropped: {str(val)}')
                continue
            target = feature_map[fname](self)
            target.build(val)
            self.targets.append(target)

    def render(self):
        deps = ' '.join(f'-m {dep}' for dep in self.dependencies)
        chain = '' if self.chain is None else self.chain
        targets = " ".join(t.render() for t in self.targets)
        return f'{self.rtype} {chain} {deps} {targets}'


default_tables = {}

register_table = Registrator(default_tables)


@register_table('filter')
class FilterTable(Table):
    default_chains = (
        'REJECT',
    )


@register_table('raw')
class RawTable(Table):
    pass


@register_table('mangle')
class MangleTable(Table):
    pass


@register_table('security')
class SecurityTable(Table):
    pass


@register_table('nat')
class NatTable(Table):
    default_chains = (
        'SNAT',
        'DNAT',
        'MASQUERADE'
    )


_default_chains = ('ACCEPT', 'DROP', 'RETURN')


class Yip():
    def __init__(self, path, default_chains=_default_chains):
        self.scope = VarScope()
        self.path = path
        self.tree = YipLoader.load(open(path))
        self.tables = {}
        self.chains = Scope({c: None for c in _default_chains})

    def build(self):
        self.scope.get_vars(self.tree)
        for table, table_class in default_tables.items():
            tnode = self.tree.get(table)
            if tnode:
                nt = table_class(self, table)
                self.tables[table] = nt
                nt.build(tnode)

    def render(self):
        return '\n\n\n'.join(o.render() for n, o in self.tables.items())
