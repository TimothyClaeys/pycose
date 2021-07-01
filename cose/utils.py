from abc import ABC, abstractmethod
from typing import Any, Callable

from cose.exceptions import CoseException


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
            cls.get_registered_classes()[the_class.fullname.upper()] = the_class
            return the_class

        return decorator

    @classmethod
    def from_id(cls, attribute: Any, allow_unknown_attributes: bool = False) -> Any:
        if isinstance(attribute, int) and attribute in cls.get_registered_classes():
            return cls.get_registered_classes()[attribute]
        elif isinstance(attribute, str) and attribute.upper() in cls.get_registered_classes():
            return cls.get_registered_classes()[attribute.upper()]
        elif isinstance(attribute, list):
            translated_list = [cls.from_id(attr) for attr in attribute]
            return translated_list
        elif hasattr(attribute, 'identifier') and attribute.identifier in cls.get_registered_classes():
            return cls.get_registered_classes()[attribute.identifier]
        else:
            if allow_unknown_attributes:
                return attribute
            else:
                raise CoseException(f"Unknown COSE attribute with value: [{cls.__name__} - {attribute}]")

    @property
    @abstractmethod
    def identifier(self):
        raise NotImplementedError()

    @property
    @abstractmethod
    def fullname(self) -> str:
        raise NotImplementedError()

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
