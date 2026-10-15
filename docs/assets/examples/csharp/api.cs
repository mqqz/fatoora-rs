using Fatoora;

const byte environment = 0; // Non-production; credentials must match.
string token = Environment.GetEnvironmentVariable("ZATCA_TOKEN")
    ?? throw new InvalidOperationException("Set ZATCA_TOKEN first");
string secret = Environment.GetEnvironmentVariable("ZATCA_SECRET")
    ?? throw new InvalidOperationException("Set ZATCA_SECRET first");
using var config = Config.New(environment);
using var client = ZatcaClient.Create(config);
using var credentials = CsidProduction.Create(environment, null, token, secret);
using var invoice = SignedInvoice.FromXml(File.ReadAllText("signed.xml"));
using var response = client.ReportSimplifiedInvoice(invoice, credentials, false, "en");
response.EnsureAccepted();
Console.WriteLine("Invoice reporting accepted");
