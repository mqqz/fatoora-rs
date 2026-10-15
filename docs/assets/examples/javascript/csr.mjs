import { readFileSync, writeFileSync } from 'node:fs';
import { CsrProperties, SigningKey } from 'fatoority';

const properties = CsrProperties.fromPropertiesStr(readFileSync('csr.properties', 'utf8'));
const key = SigningKey.generate();
const csr = properties.build(key, 0); // Non-production.
writeFileSync('csr.pem', csr.toPem());
writeFileSync('key.pem', key.toPem());
console.log('Saved csr.pem and key.pem');
