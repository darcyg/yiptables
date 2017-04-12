# Yiptables, a yaml to iptables-restore tranpiler
# Copyright (C) 2017 Victor Collod <victor.collod@prologin.org>

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from rule import Rule
from tools import (
    yip_flatten_iter,
    yip_dict_format,
    yip_format,
    Registrator,
)


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
        rule = Rule(self, scope)
        self.rules.append(rule)
        rule.build(rule_node)

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
                item_list = rule_node.pop('with_items')
                for item in yip_flatten_iter(item_list):
                    nitem = yip_format(scope, item)
                    if isinstance(nitem, str):
                        nitem = {'item': nitem}
                    assert(isinstance(nitem, dict))
                    nscope = scope.sub_scope(nitem)
                    self.add_rule(rule_node, nscope)
                continue

            if 'block' in rule_node:
                subrules = rule_node.get('rules')
                if not subrules:
                    raise SyntaxError('block has no rules attribute')
                nscope = scope.sub_scope()
                nscope.get_vars(rule_node, attr='block')
                self.build_rules(subrules, nscope)
            else:
                self.add_rule(rule_node, scope)

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


default_tables = {}

_register_table = Registrator(default_tables)


@_register_table('filter')
class FilterTable(Table):
    default_chains = (
        'REJECT',
    )


@_register_table('raw')
class RawTable(Table):
    pass


@_register_table('mangle')
class MangleTable(Table):
    pass


@_register_table('security')
class SecurityTable(Table):
    pass


@_register_table('nat')
class NatTable(Table):
    default_chains = (
        'SNAT',
        'DNAT',
        'MASQUERADE'
    )
