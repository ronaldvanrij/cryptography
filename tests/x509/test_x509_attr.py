# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import datetime
import typing

import pytest

from cryptography import x509
from cryptography.hazmat._oid import _OID_NAMES, AttributeOID, NameOID
from cryptography.hazmat.bindings._rust import x509 as rust_x509
from cryptography.x509.attributes import (
    AttributeType,
)

from ..hazmat.primitives.test_rsa import rsa_key_2048

# Make ruff happy since we're importing fixtures that pytest patches in as
# func args
__all__ = ["rsa_key_2048"]


def _make_certbuilder(private_key):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.org")])
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(777)
        .not_valid_before(datetime.datetime(1999, 1, 1))
        .not_valid_after(datetime.datetime(2020, 1, 1))
    )


class TestAttribute:
    def test_not_an_oid(self):
        sop = x509.StatementOfPossession(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]), 12345
        )
        with pytest.raises(TypeError):
            x509.Attribute(typing.cast(typing.Any, "notanoid"), sop)

    def test_repr(self):
        sop = x509.StatementOfPossession(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]), 12345
        )
        ext = x509.Attribute(AttributeOID.STATEMENT_OF_POSSESSION, sop)
        assert repr(ext) == (
            "<Attribute(oid=<ObjectIdentifier(oid=2.5.29.19, name=basicConst"
            "raints)>, value=<StatementOfPossession(ca=False, path"
            "_length=None)>)>"
        )

    def test_eq(self):
        sop = x509.StatementOfPossession(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]), 12345
        )
        ext1 = x509.Attribute(
            x509.ObjectIdentifier("1.2.3.4"),
            sop,
        )
        ext2 = x509.Attribute(
            x509.ObjectIdentifier("1.2.3.4"),
            sop,
        )
        assert ext1 == ext2

    def test_ne(self):
        ext1 = x509.Attribute(
            x509.ObjectIdentifier("1.2.3.4"),
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]),
                12345,
            ),
        )
        ext2 = x509.Attribute(
            x509.ObjectIdentifier("1.2.3.5"),
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]),
                12345,
            ),
        )
        ext3 = x509.Attribute(
            x509.ObjectIdentifier("1.2.3.4"),
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]),
                12345,
            ),
        )
        ext4 = x509.Attribute(
            x509.ObjectIdentifier("1.2.3.4"),
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]),
                12345,
            ),
        )
        assert ext1 != ext2
        assert ext1 != ext3
        assert ext1 != ext4
        assert ext1 != object()

    def test_hash(self):
        ext1 = x509.Attribute(
            AttributeOID.STATEMENT_OF_POSSESSION,
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf1")]),
                12345,
            ),
        )
        ext2 = x509.Attribute(
            AttributeOID.STATEMENT_OF_POSSESSION,
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf1")]),
                12345,
            ),
        )
        ext3 = x509.Attribute(
            AttributeOID.STATEMENT_OF_POSSESSION,
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf1")]),
                54321,
            ),
        )
        ext4 = x509.Attribute(
            AttributeOID.STATEMENT_OF_POSSESSION,
            x509.StatementOfPossession(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf2")]),
                12345,
            ),
        )
        assert hash(ext1) == hash(ext2)
        assert hash(ext1) != hash(ext3)
        assert hash(ext1) != hash(ext4)


class TestUnrecognizedAttribute:
    def test_invalid_oid(self):
        with pytest.raises(TypeError):
            x509.UnrecognizedAttribute(
                typing.cast(typing.Any, "notanoid"),
                b"somedata",
            )

    def test_eq(self):
        ext1 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext2 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        assert ext1 == ext2

    def test_ne(self):
        ext1 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext2 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x02"
        )
        ext3 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.5"), b"\x03\x02\x01"
        )
        assert ext1 != ext2
        assert ext1 != ext3
        assert ext1 != object()

    def test_repr(self):
        ext1 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        assert repr(ext1) == (
            "<UnrecognizedAttribute(oid=<ObjectIdentifier(oid=1.2.3.4, "
            "name=Unknown OID)>, value=b'\\x03\\x02\\x01')>"
        )

    def test_hash(self):
        ext1 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext2 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.4"), b"\x03\x02\x01"
        )
        ext3 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.5"), b"\x03\x02\x01"
        )
        assert hash(ext1) == hash(ext2)
        assert hash(ext1) != hash(ext3)

    def test_public_bytes(self):
        ext1 = x509.UnrecognizedAttribute(
            x509.ObjectIdentifier("1.2.3.5"), b"\x03\x02\x01"
        )
        assert ext1.public_bytes() == b"\x03\x02\x01"

        # The following creates a StatementOfPossession attribute with an
        # invalid value. The serialization code should still handle it
        # correctly by special-casing UnrecognizedAttribute.
        ext2 = x509.UnrecognizedAttribute(
            x509.oid.AttributeOID.STATEMENT_OF_POSSESSION, b"\x03\x02\x01"
        )
        assert ext2.public_bytes() == b"\x03\x02\x01"


def test_all_attribute_oid_members_have_names_defined():
    for oid in dir(AttributeOID):
        if oid.startswith("__"):
            continue
        assert getattr(AttributeOID, oid) in _OID_NAMES


def test_unknown_attribute():
    class MyAttribute(AttributeType):
        oid = x509.ObjectIdentifier("1.2.3.4")

    with pytest.raises(NotImplementedError):
        MyAttribute().public_bytes()

    with pytest.raises(NotImplementedError):
        rust_x509.encode_attribute_value(MyAttribute())
