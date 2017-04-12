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

import argparse
from loader import YipLoader
from table import default_tables
from tools import Scope, YipScope


_default_chains = ('ACCEPT', 'DROP', 'RETURN')


class Yip():
    def __init__(self, path, default_chains=_default_chains):
        self.scope = YipScope()
        self.path = path
        self.tree = YipLoader.load(open(path))
        self.tables = {}
        self.chains = Scope({c: None for c in _default_chains})
        self.built = False

    def _build(self):
        self.scope.get_vars(self.tree)
        for table, table_class in default_tables.items():
            tnode = self.tree.get(table)
            if tnode:
                nt = table_class(self, table)
                self.tables[table] = nt
                nt.build(tnode)
        self.built = True

    def render(self):
        if not self.built:
            self._build()
        return '\n\n\n'.join(o.render() for n, o in self.tables.items())


if __name__ == '__main__':
    class Options():
        pass
    options = Options()
    parser = argparse.ArgumentParser()
    parser.add_argument('firewall', help='source file')
    print(Yip(parser.parse_args().firewall).render())
