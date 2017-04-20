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

from ast_nodes import Not
from features import feature_map


class TypeMap(dict):
    def __init__(self, it):
        super().__init__()
        for e in it:
            self.add(e)

    def add(self, e):
        et = type(e)
        s = self.get(et)
        if s:
            s.add(e)
        else:
            self[et] = {e}


class Rule():
    def __init__(self, table, scope=None, rtype='-A'):
        self.scope = table.scope.sub_scope() if scope is None else scope
        self.table = table
        self.dependencies = set()
        self.targets = []
        self.chain = None
        self.rtype = rtype
        self.used_features = set()
        self.tokens = []

    def check(self):
        assert(self.chain)

    def build(self, node):
        node_scope = self.scope.rule
        node_scope.get_vars(node, None, self.scope, node_scope, to_rule=True)
        print(f'node: {node}')
        print(f'rule scope: {node_scope}')
        for fname, val in node_scope.items():
            if fname not in feature_map:
                raise SyntaxError(f'Unknown feature: {fname}')

            isnot = isinstance(val, Not)
            target = feature_map[fname](self, negated=isnot)
            self.targets.append(target)
            target.build(val.value if isnot else val)

        tm = TypeMap(self.targets)
        for target in self.targets:
            target.check(tm)

        self.tokens.sort(key=lambda x: x[0])
        self.check()

    def render(self):
        tokens = ' '.join(t[1] for t in self.tokens)
        return f'{self.rtype} {self.chain} {tokens}'
