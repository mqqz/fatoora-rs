"""Owned binary outputs must work without optional array libraries."""
from pathlib import Path
import base64

from fatoora import Csr, Signer, SigningKey

FIXTURES = Path(__file__).resolve().parents[3] / "fatoora-core/tests/fixtures/sdk-parity"


def test_key_der_survives_owner_close():
    key = SigningKey.generate()
    der = key.to_der()
    key.close()
    assert isinstance(der, bytes)
    with SigningKey.from_der(der) as restored:
        assert restored.to_der() == der
        with SigningKey.from_pem(restored.to_pem()) as pem_restored:
            assert pem_restored.to_der() == der


def test_csr_der_and_extension_copies():
    der = (FIXTURES / "cases/csr-en-individual-nonproduction/sdk.csr.der").read_bytes()
    csr = Csr.from_der(der)
    assert csr.to_der() == der
    assert base64.b64decode(csr.to_base64()) == der
    extensions = csr.extension_values_der()
    csr.close()
    assert extensions and all(isinstance(value, bytes) and value for value in extensions)


def test_certificate_der_matches_independent_fixture():
    der = (FIXTURES / "credentials/certificate.der").read_bytes()
    key = (FIXTURES / "credentials/private-key.der").read_bytes()
    signer = Signer.from_der(der, key)
    actual = signer.certificate_der()
    signer.close()
    assert isinstance(actual, bytes) and actual == der
