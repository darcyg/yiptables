
from collections import ChainMap
from tools import yip_ld_iter, yip_format
from ast_nodes import Not, Rule, IfDef


class Scope(ChainMap):
    def sub_scope(self, local=None):
        return self.new_child(local)

    def get_vars(self, node, attr='vars', vars=None, rules=None, to_rule=False):
        if attr is not None:
            node = node.get(attr)
            if node is None:
                return
        for k, v in yip_ld_iter(node):
            scope = rules if to_rule else vars

            if isinstance(k, Rule):
                assert(rules is not None)
                scope = rules
                k = k.value
            elif isinstance(k, IfDef):
                istrue = k.value in scope
                if isinstance(v, dict):
                    if_block = v.get('then')
                    if if_block is None:
                        if_block = v
                    else_block = v.get('else')
                    sub_block = if_block if istrue else else_block
                else:
                    sub_block = v if istrue else None
                if sub_block is not None:
                    scope.get_vars(sub_block, None, vars, rules, to_rule)
                continue

            if isinstance(v, Not):
                v = v.value
                tr = Not
            else:
                def tr(x):
                    return x
            scope[k] = tr(yip_format(vars, v))


class YipScope(Scope):
    def __init__(self, *maps, rules=None):
        super().__init__(*maps)
        self.rule = Scope(*(rules if rules else {}))

    def sub_scope(self, local=None, rlocal=None):
        nscope = super().sub_scope(local=local)
        nscope.rule = self.rule.sub_scope(local=rlocal)
        return nscope

    def get_vars(self, node, attr='vars', vars=None, rules=None, *a, **kw):
        var_scope = self if vars is None else vars
        rule_scope = self.rule if rules is None else rules
        super().get_vars(node, attr, var_scope, rule_scope, *a, **kw)
