from pathlib import Path
csr_props_path = Path(__file__).resolve().parents[3] / "fatoora-core" / "tests" / "fixtures" / "csr-configs" / "csr-config-example-EN.properties"

# --8<-- [start:example]
from fatoora.config import Environment
from fatoora.csr import CsrProperties

# csr_props_path = "path/to/csr.properties"
# Read the CSR properties from the file as a string
props_str = ""
with open(csr_props_path, "r", encoding="utf-8") as f:
    props_str = f.read()

props = CsrProperties.parse(props_str)

    bundle = props.build_with_rng(Environment.NON_PRODUCTION)

    csr_b64 = bundle.csr.to_base64()
    key_pem = bundle.key.to_pem()
    assert csr_b64
    assert "BEGIN PRIVATE KEY" in key_pem
    # --8<-- [end:example]
