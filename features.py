from tools import (
    yip_format,
    yip_stringize,
    Registrator
)


feature_map = {}

register_feature = Registrator(feature_map)


class BaseTarget():
    def __init__(self, rule, key=None):
        self.rule = rule
        self.args = []

    def add_dep(self, dep):
        assert(type(dep) is str)
        self.rule.dependencies.add(dep)

    def add_target(self, target):
        assert(type(target) is str)
        self.args.append(target)

    @property
    def scope(self):
        return self.rule.scope

    def resolve(self, string):
        return yip_format(self.rule.scope, yip_stringize(string))

    @property
    def has_comment(self):
        return self.rule.has_comment

    @has_comment.setter
    def has_comment(self, val):
        self.rule.has_comment = val

    def render(self):
        return ' '.join(self.args)


@register_feature('target')
class Target(BaseTarget):
    def build(self, value):
        rval = self.resolve(value)
        comment = rval.strip().split()
        target = comment.pop(0).upper()

        if target not in self.rule.table.chains:
            raise SyntaxError(f'Undefined target: {target}')
        self.add_target(f'-j {target}')

        if comment:
            if self.has_comment:
                raise SyntaxError(
                    'Multiple comments inside the same rule'
                    '(maybe both in target and comment)'
                )
            self.has_comment = True

            self.add_dep('comment')
            comment.insert(0, target.capitalize())
            com_body = ' '.join(comment)
            self.add_target('--comment "%s"' % com_body.replace('"', '\\"'))
