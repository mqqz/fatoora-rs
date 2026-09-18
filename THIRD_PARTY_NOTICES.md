# Third-party notices

Original fatoora-rs code is available under `MIT OR Apache-2.0`. The materials
below retain their applicable upstream terms. Paths are relative to the repository
root; a package may contain only a subset. Existing file notices must be retained.

Source comparisons used ZATCA Java SDK `238-R3.4.8` on 2026-09-11. Items marked
unresolved require clarification or replacement; this notice does not grant
permission for them. Bundled binary dependencies still require a separate notice
review before a complete distribution-compliance claim can be made.

## UBL schemas

Files: `fatoora-core/assets/schemas/UBL2.1/xsd/`.
Source: [OASIS UBL 2.1 OS, 4 November 2013](https://docs.oasis-open.org/ubl/os-UBL-2.1/),
obtained through the [ZATCA SDK](https://zatca.gov.sa/en/E-Invoicing/SystemsDevelopers/ComplianceEnablementToolbox/Pages/DownloadSDK.aspx).

The eleven OASIS schemas carry Copyright (c) OASIS Open 2013 and their full
permission notices. They match the SDK copies without modification. The four
files below have separate upstream origins:

- `common/CCTS_CCT_SchemaModule-2.1.xsd`: Copyright (C) UN/CEFACT (2006).
  Unmodified SDK copy; the full permission notice is embedded in the file.
- `common/UBL-XAdESv132-2.1.xsd` and `common/UBL-XAdESv141-2.1.xsd`: OASIS adaptations
  of [ETSI XAdES v1.3.2](https://uri.etsi.org/01903/v1.3.2/XAdES.xsd) and
  [v1.4.1](https://uri.etsi.org/01903/v1.4.1/XAdESv141.xsd). Our copies match the
  official OASIS UBL 2.1 files byte-for-byte:
  [v1.3.2](https://docs.oasis-open.org/ubl/os-UBL-2.1/xsd/common/UBL-XAdESv132-2.1.xsd)
  and [v1.4.1](https://docs.oasis-open.org/ubl/os-UBL-2.1/xsd/common/UBL-XAdESv141-2.1.xsd).
  The OASIS headers are retained. ETSI publishes BSD-3-Clause terms with its
  XAdES repository; that notice is reproduced below with its source version.
- `common/UBL-xmldsig-core-schema-2.1.xsd`: derived from the W3C XML Signature
  schema. Copyright 2001 The Internet Society and W3C (Massachusetts Institute
  of Technology, Institut National de Recherche en Informatique et en
  Automatique, Keio University). All Rights Reserved. OASIS's DOCTYPE changes
  are described in the file header. Mohamad Alsadhan modified the serial-number
  type on 2025-12-18 (commit `1fc08cdcfc5d34bda07b56aba4c9dd1aa7a63d6d`), adding
  `X509SerialNumberString` with pattern `[0-9]+` and using it instead of `integer`
  for `X509SerialNumber`. The applicable W3C notice follows.

### ETSI XAdES repository notice (BSD-3-Clause)

Source: [ETSI XAdES repository, tag v1.3.1](https://forge.etsi.org/rep/esi/x19_13201_xades/-/raw/v1.3.1/LICENSE).
This notice comes from the 2024 repository release; the bundled schemas remain
the unchanged OASIS UBL 2.1 copies from 2013.

Copyright 2024 ETSI

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.

### W3C SOFTWARE NOTICE AND LICENSE

Source: <https://www.w3.org/Consortium/Legal/copyright-software-19980720>.

Copyright © 1994-2002 World Wide Web Consortium, (Massachusetts Institute of
Technology, Institut National de Recherche en Informatique et en Automatique,
Keio University). All Rights Reserved. http://www.w3.org/Consortium/Legal/

This W3C work (including software, documents, or other related items) is being
provided by the copyright holders under the following license. By obtaining,
using and/or copying this work, you (the licensee) agree that you have read,
understood, and will comply with the following terms and conditions:

Permission to use, copy, modify, and distribute this software and its
documentation, with or without modification, for any purpose and without fee or
royalty is hereby granted, provided that you include the following on ALL copies
of the software and documentation or portions thereof, including modifications,
that you make:

1. The full text of this NOTICE in a location viewable to users of the
   redistributed or derivative work.
2. Any pre-existing intellectual property disclaimers, notices, or terms and
   conditions. If none exist, a short notice of the following form (hypertext
   is preferred, text is permitted) should be used within the body of any
   redistributed or derivative code: "Copyright © [$date-of-software] World Wide
   Web Consortium, (Massachusetts Institute of Technology, Institut National de
   Recherche en Informatique et en Automatique, Keio University). All Rights
   Reserved. http://www.w3.org/Consortium/Legal/"
3. Notice of any changes or modifications to the W3C files, including the date
   changes were made. (We recommend you provide URIs to the location from which
   the code is derived.)

THIS SOFTWARE AND DOCUMENTATION IS PROVIDED "AS IS," AND COPYRIGHT HOLDERS MAKE
NO REPRESENTATIONS OR WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO, WARRANTIES OF MERCHANTABILITY OR FITNESS FOR ANY PARTICULAR PURPOSE OR THAT
THE USE OF THE SOFTWARE OR DOCUMENTATION WILL NOT INFRINGE ANY THIRD PARTY
PATENTS, COPYRIGHTS, TRADEMARKS OR OTHER RIGHTS.

COPYRIGHT HOLDERS WILL NOT BE LIABLE FOR ANY DIRECT, INDIRECT, SPECIAL OR
CONSEQUENTIAL DAMAGES ARISING OUT OF ANY USE OF THE SOFTWARE OR DOCUMENTATION.

The name and trademarks of copyright holders may NOT be used in advertising or
publicity pertaining to the software without specific, written prior permission.
Title to copyright in this software and any associated documentation will at all
times remain with copyright holders.

## ZATCA test samples

Source: ZATCA Java SDK `238-R3.4.8`, linked above.

| Repository files under `fatoora-core/tests/fixtures/` | SDK source | Changes |
| --- | --- | --- |
| `invoices/Standard/**` and `invoices/Simplified/**` (19 XML files) | Corresponding paths under `Data/Samples/` | None |
| `invoices/sample-simplified-invoice.xml` | `Data/Samples/Simplified/Invoice/Simplified_Invoice.xml` | Added final newline |
| `csr-configs/*.properties` (5 files) | Corresponding files under `Data/Input/` | None |
| `certs/zatca_cert_b64.txt` | `Data/Certificates/cert.pem` | Local double-base64 and SDK single-base64 decode to identical certificate DER |
| `pkeys/test_zatca_pkey.der` | `Data/Certificates/ec-secp256k1-priv-key.pem` | Local DER and SDK base64-encoded PEM have the same public-key identity |

The SDK contains an LGPL v3 license text, but its scope for these sample files
has not been established. Confirm redistribution terms or replace the samples
with independently generated fixtures before treating this question as resolved.

The SDK parity corpus under `fatoora-core/tests/fixtures/sdk-parity/` additionally
records CLI outputs, signed XML, generated test CSRs/keys, canonical bytes, and
SignedProperties preimages produced by SDK `238-R3.4.8`. Each case's manifest
entry identifies its input source. The payable-rounding, exempt, zero-rated,
and document-charge inputs reuse the existing SDK XML samples; CSR inputs reuse
its English/Arabic properties. The certificate/key are the existing dummy test
credentials in decoded DER form. These additions preserve the same unresolved
sample redistribution question above. No SDK JAR or executable is bundled.
The Java adapters in `scripts/sdk-parity/` are repository-authored test tooling.

## Other origins to confirm

- `fatoora-core/assets/templates/*.xml` (3 files), and related XML fragments in
  `fatoora-core/src/invoice/sign.rs`: confirm independent authorship or record
  their source and applicable terms. UBL/XMLDSig/XAdES syntax alone does not
  establish copying or a license.
- `fatoora-core/tests/fixtures/csrs/test_zatca_en1.csr`: base64-encoded DER CSR;
  its public key differs from the local sample key. Generation provenance is
  unresolved.
- `docs/assets/images/crab-logo.{svg,png,webp}`: appears to adapt Ferris with
  additional artwork. [Original Ferris](https://www.rustacean.net/) is by Karen
  Rustad Tölva, who has waived copyright and related rights to that work to the
  extent possible under law. The exact base image and rights to the additions
  remain to be confirmed.
- `CODE_OF_CONDUCT.md`: adapted from
  [Contributor Covenant version 2.0](https://www.contributor-covenant.org/version/2/0/code_of_conduct/),
  originally authored by Coraline Ada Ehmke. Existing attribution, including the
  Mozilla enforcement-ladder reference, is retained. The applicable version-2.0
  license grant still needs verification and an explicit reference here.

## Historical files

The current tree contains no Schematron XSL files or PDF-A3 invoice samples.
Git history retains the following materials; their historical distribution
requirements remain open:

- `fatoora-core/assets/schematrons/CEN-EN16931-UBL.xsl`: matches SDK `238-R3.4.8`;
  its header claims LGPL v3 through EUPL 1.2 compatibility. The exact upstream
  revision and basis for that conversion remain unverified.
- `fatoora-core/assets/schematrons/20210819_ZATCA_E-invoice_Validation_Rules.xsl`:
  header declares Copyright 2021 ZATCA, LGPL v3; differs from SDK `238-R3.4.8`.
  Both XSL files were removed in commit `8ffeccf153428f262c56c256046416b67fda0d42`.
- `fatoora-core/tests/fixtures/invoices/PDF-A3/*.pdf` (16 files): exact SDK sample
  copies removed in commit `bb473ec`. Sample-license scope remains unresolved.

For old distributions containing the stylesheets, review the applicable LGPL/GPL
texts and source requirements. This notice does not retroactively update those
archives or resolve their outstanding permissions.
