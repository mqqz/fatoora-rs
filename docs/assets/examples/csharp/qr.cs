using Fatoora;

using var invoice = SignedInvoice.FromXml(File.ReadAllText("signed.xml"));
string payload = invoice.QrCode();
File.WriteAllText("qr.txt", payload);
Console.WriteLine(payload);
