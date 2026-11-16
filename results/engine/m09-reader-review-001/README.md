# Storage-reader follow-up after the M09 full check

The full local check passed 438 Python tests with unchanged sources/controls. A subsequent storage-only correction verifies declared parts directly even when a correct full archive exists. Four chunk tests include that negative case; the whole Python suite is rerun in tests.log. All 37 qualified compilation inputs and scientific payloads remain unchanged. The earlier frozen reader is preserved; these source copies record the later active reader. Fresh hosted CI covers the resulting code.
