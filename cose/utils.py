from abc import ABC, abstractmethod
from typing import Any, Callable


class _CoseAttribute(ABC):
    @classmethod
    def default_parser(cls, value):
        return value

    value_parser: Callable = default_parser

    @classmethod
    @abstractmethod
    def get_registered_classes(cls):
        raise NotImplementedError()

    @classmethod
    def register_attribute(cls) -> Callable:
        def decorator(the_class: '_CoseAttribute'):
            cls.get_registered_classes()[the_class.identifier] = the_class
            cls.get_registered_classes()[the_class.fullname] = the_class
            return the_class

        return decorator

    @classmethod
    def from_id(cls, attribute: Any) -> Any:
        if isinstance(attribute, int):
            return cls.get_registered_classes()[attribute]
        elif isinstance(attribute, str):
            return cls.get_registered_classes()[attribute.upper()]
        elif hasattr(attribute, 'identifier'):
            return cls.get_registered_classes()[attribute.identifier]
        else:
            return attribute

    @property
    @abstractmethod
    def identifier(self):
        raise NotImplementedError()

    @property
    @abstractmethod
    def fullname(self) -> str:
        raise NotImplementedError()

    def __int__(self):
        return self.identifier

    def __str__(self):
        return self.fullname

    def __eq__(self, other: '_CoseAttribute'):
        return self.identifier == other.identifier

    def __ne__(self, other: '_CoseAttribute'):
        return self.identifier != other.identifier

    def __lt__(self, other: '_CoseAttribute'):
        return self.identifier < other.identifier

    def __le__(self, other: '_CoseAttribute'):
        return self.identifier <= other.identifier

    def __gt__(self, other: '_CoseAttribute'):
        return self.identifier > other.identifier

    def __ge__(self, other: '_CoseAttribute'):
        return self.identifier >= other.identifier

    # def __hash__(self):
    #     return hash((self.identifier, self.fullname))

    def __repr__(self):
        return f'<{self.fullname}: {self.identifier}>'


def truncate(payload: bytes) -> str:
    return f'{payload[:5]} ... ({len(payload)} B)'
