from pathlib import Path
from fatoora.config import Environment
from fatoora.csr import CsrProperties, SigningKey

with CsrProperties.parse_csr_config_file("csr.properties") as properties:
    with SigningKey.generate() as key:
        with properties.build(key, Environment.NON_PRODUCTION) as csr:
            Path("csr.pem").write_text(csr.to_pem(), encoding="utf-8")
            Path("key.pem").write_text(key.to_pem(), encoding="utf-8")
print("Saved csr.pem and key.pem")
