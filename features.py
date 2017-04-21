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

from meta import meta, BaseMeta, YipSyntaxError
from tools import (
    yip_get_single_var,
    yip_format,
    yip_listize,
    yip_stringize,
    Registrator
)


feature_map = {}

_register_feature = Registrator(feature_map)


class BaseTarget(BaseMeta):
    supports_negation = False

    def __meta__(self):
        return meta(self.rule)

    def __init__(self, rule, negated=False):
        self.rule = rule
        self.args = []
        if negated:
            assert(self.supports_negation)
        self.negated = negated

    @property
    def tneg(self):
        return ['!'] if self.negated else []

    def add_dep(self, dep):
        assert(type(dep) is str)
        self.add_target(f'-m {dep}', k=5)
        self.rule.dependencies.add(dep)

    def add_target(self, target, k=10):
        assert(type(target) is str)
        self.rule.tokens.append((k, target))

    @property
    def scope(self):
        return self.rule.scope

    def resolve(self, string):
        return yip_format(self.scope, string)

    def str_resolve(self, string):
        return yip_format(self.scope, yip_stringize(string))

    def add_conflict(self, *items):
        self.conflicts.add(set(items))

    def __init_subclass__(cls):
        if 'conflicts' not in cls.__dict__:
            cls.conflicts = set()

        if hasattr(cls, 'self_conflict') and cls.self_conflict:
            cls.__dict__['conflicts'].add(cls)

    def check(self, typemap):
        if not hasattr(self, 'conflicts'):
            return
        for confl_type in self.conflicts:
            ilist = typemap.get(confl_type)
            if ilist and any(e is not self for e in ilist):
                raise YipSyntaxError(
                    self,
                    f'{confl_type} conflicts with {self}'
                )


class ExclusiveTarget(BaseTarget):
    self_conflict = True


class Negable(BaseTarget):
    supports_negation = True


@_register_feature('chain')
class ChainTarget(ExclusiveTarget):
    def build(self, value):
        self.rule.chain = self.str_resolve(value)


@_register_feature('target')
class Target(ExclusiveTarget):
    def build(self, value):
        rval = self.str_resolve(value)
        comment = rval.strip().split()
        target = comment.pop(0).upper()

        if target not in self.rule.table.chains:
            raise YipSyntaxError(rval, f'Undefined target: {target}')
        self.add_target(f'-j {target}', k=1)

        if comment:
            self.add_dep('comment')
            comment.insert(0, target.capitalize())
            com_body = ' '.join(comment)
            self.add_target('--comment "%s"' % com_body.replace('"', '\\"'))


@_register_feature('proto')
class Proto(ExclusiveTarget, Negable):
    def build(self, value):
        proto = self.str_resolve(value).lower()
        if proto in ('', 'all', 'any'):
            if self.negated:
                raise YipSyntaxError(
                    self,
                    f"Can't negate the '{proto}' proto"
                )
            return

        if proto not in ('tcp', 'udp', 'icmp'):
            raise YipSyntaxError(self, f'Unknown protocol: `{proto}`')

        self.add_target(' '.join(self.tneg + ['-p', proto]), k=2)


@_register_feature('iface')
class IFace(ExclusiveTarget, Negable):
    def build(self, value):
        self.add_target(' '.join(self.tneg + ['-i', self.str_resolve(value)]))


@_register_feature('oface')
class OFace(ExclusiveTarget, Negable):
    def build(self, value):
        self.add_target(' '.join(self.tneg + ['-o', self.str_resolve(value)]))


@_register_feature('state')
class State(ExclusiveTarget):
    def build(self, value):
        self.add_dep('state')
        states = ','.join(self.resolve(yip_listize(value)))
        self.add_target(f'--state {states}')


class PortTarget(ExclusiveTarget, Negable):
    def build(self, value):
        svar = yip_get_single_var(self.scope, value)
        plist = self.resolve(list(map(
            yip_stringize,
            yip_listize(svar if svar else value)
        )))
        need_multiset = len(plist) > 1 or self.negated
        if need_multiset:
            self.add_dep('multiport')
        opt_name = self.multi_opt_name if need_multiset else self.opt_name
        self.add_target(' '.join(
            [f'--{opt_name}'] + self.tneg + [','.join(plist)]
        ))


@_register_feature('dport', 'dports')
class DPort(PortTarget):
    opt_name = 'dport'
    multi_opt_name = 'dports'


@_register_feature('sport', 'sports')
class SPort(PortTarget):
    opt_name = 'sport'
    multi_opt_name = 'sports'


@_register_feature('saddr')
class SAddr(ExclusiveTarget, Negable):
    def build(self, value):
        self.add_target(' '.join(self.tneg + ['-s', self.str_resolve(value)]))


@_register_feature('daddr')
class DAddr(ExclusiveTarget, Negable):
    def build(self, value):
        self.add_target(' '.join(self.tneg + ['-d', self.str_resolve(value)]))


@_register_feature('to-saddr')
class ToSAddr(ExclusiveTarget):
    def build(self, value):
        self.add_target(' '.join(
            self.tneg + ['--to-source', self.str_resolve(value)]
        ))


@_register_feature('to-daddr')
class ToDAddr(ExclusiveTarget):
    def build(self, value):
        self.add_target(' '.join(
            self.tneg + ['--to-destination', self.str_resolve(value)]
        ))


@_register_feature('icmp-type')
class IcmpType(ExclusiveTarget, Negable):
    def build(self, ovalue):
        value = self.resolve(ovalue)
        if isinstance(value, int):
            val = str(value)
        elif isinstance(value, str):
            if value.lower() == 'all':
                val = '255'
            else:
                val = str(int(value))
        else:
            raise YipSyntaxError(
                self,
                f"icmp-type requires a numeric parameter "
                f"or 'all', got: `{ovalue}`"
            )
        self.add_target(' '.join(['--icmp-type'] + self.tneg + [val]))
