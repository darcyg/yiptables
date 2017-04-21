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

import yaml
import os.path
from ast_nodes import Not, Rule, IfDef
from yaml.resolver import Resolver
from yaml.composer import Composer
from yaml.reader import Reader
from yaml.scanner import Scanner
from yaml.parser import Parser
from constructor import YipConstructor as YipCons
from meta import BaseMeta, Meta


# yaml.Loader,
class YipLoader(BaseMeta, Reader, Scanner, Parser, Composer, YipCons, Resolver):
    def __init__(self, stream):
        self.meta = Meta(stream, 1, 1)
        self._root = os.path.split(stream.name)[0]
        Reader.__init__(self, stream)
        Scanner.__init__(self)
        Parser.__init__(self)
        Composer.__init__(self)
        YipCons.__init__(self)
        Resolver.__init__(self)

    def import_handler(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, YipLoader)

    def rule_handler(self, node):
        return Rule(self.construct_scalar(node))

    def ifdef_handler(self, node):
        return IfDef(self.construct_scalar(node))

    def not_handler(self, node):
        return Not(self.construct_scalar(node))

    def load(fd):
        return yaml.load(fd, YipLoader)


YipLoader.add_constructor('!import', YipLoader.import_handler)
YipLoader.add_constructor('!rule', YipLoader.rule_handler)
YipLoader.add_constructor('!not', YipLoader.not_handler)
YipLoader.add_constructor('!ifdef', YipLoader.ifdef_handler)
