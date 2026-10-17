import { readFileSync } from 'node:fs';
import { Config, Xml } from 'fatoority';

const config = Config.new_(0); // Non-production.
const xml = readFileSync('invoice.xml', 'utf8');
if (process.argv.includes('--zatca')) {
  const report = JSON.parse(Xml.validateZatca(config, xml, JSON.stringify({
    previous_invoice_hash: readFileSync('previous-hash.txt', 'utf8').trim(),
  })));
  console.log(JSON.stringify(report, null, 2));
  process.exitCode = report.is_valid ? 0 : 1;
} else {
  Xml.validate(config, xml);
  console.log('XSD valid');
}
