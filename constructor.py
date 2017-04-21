import logging
from yaml.constructor import BaseConstructor, ConstructorError
from yaml.nodes import MappingNode
from ast_nodes import DictNode, ListNode, StrNode
from meta import Meta


class YipConstructor(BaseConstructor):
    def _node_meta(self, node):
        mark = node.start_mark
        return Meta(mark.name, mark.line + 1, mark.column + 1)

    def construct_scalar(self, node, deep=False):
        scalar = StrNode(super().construct_scalar(node))
        scalar.meta = self._node_meta(node)
        return scalar

    def construct_sequence(self, node, deep=False):
        seq = ListNode(super().construct_sequence(node))
        seq.meta = self._node_meta(node)
        return seq

    def construct_mapping(self, node, deep=False):
        if not isinstance(node, MappingNode):
            raise ConstructorError(
                None,
                None,
                f'expected a mapping node, but found {node.id}',
                node.start_mark
            )

        mapping = DictNode()
        mapping.meta = self._node_meta(node)

        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                hash(key)
            except TypeError as exc:
                raise ConstructorError(
                    'while constructing a mapping', node.start_mark,
                    f'found unacceptable key ({exc})', key_node.start_mark)
            if key in mapping:
                logging.warn(
                    'While constructing a mapping from {1}, '
                    'line {2}, column {3}, found a duplicate dict key ({0}). '
                    'Using last defined value only.'.format(key, *mapping.pos)
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping
