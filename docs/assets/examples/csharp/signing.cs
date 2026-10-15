using Fatoora;

using var signer = Signer.FromPem(File.ReadAllText("certificate.pem"), File.ReadAllText("private-key.pem"));
using var invoice = FinalizedInvoice.FromXml(File.ReadAllText("invoice.xml"));
using var signed = signer.Sign(invoice); // Consumes the invoice's inner state.
File.WriteAllText("signed.xml", signed.IntoXml());
Console.WriteLine("Saved signed.xml");
