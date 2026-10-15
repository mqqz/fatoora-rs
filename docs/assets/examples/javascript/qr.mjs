import { readFileSync, writeFileSync } from 'node:fs';
import { SignedInvoice } from 'fatoority';

const invoice = SignedInvoice.fromXml(readFileSync('signed.xml', 'utf8'));
const payload = invoice.qrCode();
writeFileSync('qr.txt', payload);
console.log(payload);
