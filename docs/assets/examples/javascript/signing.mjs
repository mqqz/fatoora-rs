import { readFileSync, writeFileSync } from 'node:fs';
import { Signer } from 'fatoority';

const signer = Signer.fromPem(
  readFileSync('certificate.pem', 'utf8'), readFileSync('private-key.pem', 'utf8'),
);
writeFileSync('signed.xml', signer.signXml(readFileSync('invoice.xml', 'utf8')));
console.log('Saved signed.xml');
