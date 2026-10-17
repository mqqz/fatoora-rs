using Fatoora;
using System.Text.Json;

using var config = Config.New(0); // Non-production.
string xml = File.ReadAllText("invoice.xml");
if (args.Contains("--zatca"))
{
    string options = JsonSerializer.Serialize(new {
        previous_invoice_hash = File.ReadAllText("previous-hash.txt").Trim()
    });
    string json = Xml.ValidateZatca(config, xml, options);
    Console.WriteLine(json);
    using var report = JsonDocument.Parse(json);
    Environment.ExitCode = report.RootElement.GetProperty("is_valid").GetBoolean() ? 0 : 1;
}
else
{
    Xml.Validate(config, xml);
    Console.WriteLine("XSD valid");
}
