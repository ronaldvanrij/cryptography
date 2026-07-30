# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import abc
import typing
from collections.abc import Iterable

from cryptography.hazmat._oid import AttributeOID

# from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.base import Certificate
from cryptography.x509.name import Name
from cryptography.x509.oid import ObjectIdentifier

AttributeTypeVar = typing.TypeVar(
    "AttributeTypeVar", bound="AttributeType", covariant=True
)


def _make_sequence_methods(field_name: str):
    def len_method(self) -> int:
        return len(getattr(self, field_name))

    def iter_method(self):
        return iter(getattr(self, field_name))

    def getitem_method(self, idx):
        return getattr(self, field_name)[idx]

    return len_method, iter_method, getitem_method


class AttributeNotFound(Exception):
    def __init__(self, msg: str, oid: ObjectIdentifier) -> None:
        super().__init__(msg)
        self.oid = oid


class AttributeType(metaclass=abc.ABCMeta):
    oid: typing.ClassVar[ObjectIdentifier]

    def public_bytes(self) -> bytes:
        """
        Serializes the attribute type to DER.
        """
        raise NotImplementedError(
            f"public_bytes is not implemented for attribute type {self!r}"
        )


class Attribute(typing.Generic[AttributeTypeVar]):
    def __init__(self, oid: ObjectIdentifier, value: AttributeTypeVar) -> None:
        if not isinstance(oid, ObjectIdentifier):
            raise TypeError(
                "oid argument must be an ObjectIdentifier instance."
            )
        self._oid = oid
        self._value = value

    @property
    def oid(self) -> ObjectIdentifier:
        return self._oid

    @property
    def value(self) -> AttributeTypeVar:
        return self._value

    def __repr__(self) -> str:
        return f"<Attribute(oid={self.oid},value={self.value})>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Attribute):
            return NotImplemented

        return self.oid == other.oid and self.value == other.value

    def __hash__(self) -> int:
        return hash((self.oid, self.value))


class Attributes:
    def __init__(self, attributes: Iterable[Attribute[AttributeType]]) -> None:
        self._attributes = list(attributes)

    def get_attribute_for_oid(
        self, oid: ObjectIdentifier
    ) -> Attribute[AttributeType]:
        for attr in self:
            if attr.oid == oid:
                return attr

        raise AttributeNotFound(f"No {oid} attribute was found", oid)

    __len__, __iter__, __getitem__ = _make_sequence_methods("_attributes")

    def __repr__(self) -> str:
        return f"<Attributes({self._attributes})>"


class StatementOfPossession(AttributeType):
    oid = AttributeOID.STATEMENT_OF_POSSESSION

    def __init__(
        self,
        issuer: Name,
        serialnumber: int,
        cert: Certificate | None = None,
    ) -> None:
        self._issuer = issuer
        self._serialnumber = serialnumber
        self._cert = cert

    def __repr__(self) -> str:
        return (
            f"<StatementOfPossession(issuer={self._issuer}, "
            f"serialnumber={self._serialnumber}, cert={self._cert})>"
        )

    def public_bytes(self) -> bytes:
        return b""  # rust_x509.encode_extension_value(self)


class UnrecognizedAttribute(AttributeType):
    def __init__(
        self,
        oid: ObjectIdentifier,
        value: bytes,
        _tag: int | None = None,
    ) -> None:
        self._oid = oid
        self._value = value
        self._tag = _tag

    @property
    def oid(self) -> ObjectIdentifier:  # type: ignore[override]
        return self._oid

    @property
    def value(self) -> bytes:
        return self._value

    def __repr__(self) -> str:
        return f"<UnrecognizedAttribute(oid={self.oid}, value={self.value!r})>"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, UnrecognizedAttribute):
            return NotImplemented

        return (
            self.oid == other.oid
            and self.value == other.value
            and self._tag == other._tag
        )

    def __hash__(self) -> int:
        return hash((self.oid, self.value, self._tag))
