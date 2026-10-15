import { readFileSync } from 'node:fs';
import { Config, CsidProduction, SignedInvoice, ZatcaClient } from 'fatoority';

const environment = 0; // Non-production; credentials must match.
const token = process.env.ZATCA_TOKEN;
const secret = process.env.ZATCA_SECRET;
if (!token || !secret) throw new Error('Set ZATCA_TOKEN and ZATCA_SECRET first');
const client = new ZatcaClient(Config.new_(environment));
const credentials = CsidProduction.create(environment, null, token, secret);
const invoice = SignedInvoice.fromXml(readFileSync('signed.xml', 'utf8'));
const response = await client.reportSimplifiedInvoice(invoice, credentials, false, 'en');
response.ensureAccepted();
console.log('Invoice reporting accepted');
