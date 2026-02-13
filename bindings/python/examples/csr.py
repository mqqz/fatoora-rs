from pathlib import Path
csr_props_path = Path(__file__).resolve().parents[3] / "fatoora-core" / "tests" / "fixtures" / "csr-configs" / "csr-config-example-EN.properties"
csr_props_path = csr_props_path.resolve()
# --8<-- [start:example]
from fatoora.config import Environment
from fatoora.csr import CsrProperties, SigningKey

# csr_props_path = "path/to/csr.properties"
props = CsrProperties.parse_csr_config_file(str(csr_props_path))
key = SigningKey.generate()
csr = props.build(key, Environment.NON_PRODUCTION)

csr_b64 = csr.to_base64()
key_pem = key.to_pem()
assert csr_b64
assert "BEGIN PRIVATE KEY" in key_pem
# --8<-- [end:example]
