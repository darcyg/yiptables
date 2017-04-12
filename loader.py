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
from tools import Not, Rule


class YipLoader(yaml.Loader):
    def __init__(self, stream):
        self._root = os.path.split(stream.name)[0]
        super().__init__(stream)

    def include_handler(self, node):
        filename = os.path.join(self._root, self.construct_scalar(node))
        with open(filename, 'r') as f:
            return yaml.load(f, YipLoader)

    def rule_handler(self, node):
        return Rule(self.construct_scalar(node))

    def not_handler(self, node):
        return Not(self.construct_scalar(node))

    @classmethod
    def load(cls, fd):
        return yaml.load(fd, cls)


YipLoader.add_constructor('!import', YipLoader.include_handler)
YipLoader.add_constructor('!rule', YipLoader.rule_handler)
YipLoader.add_constructor('!not', YipLoader.not_handler)
