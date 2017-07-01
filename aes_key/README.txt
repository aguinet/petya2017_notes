AES key recovery experience
===========================

The project ``ransom_key`` is a binary that will generate a 2048-bit RSA key,
an AES key and export this AES key with the generated RSA key. AFAIK, this is
the only way to export a generated AES key.

The Python3 script will then decrypt the AES key using the export private RSA
key. The recovered AES key can then be used for instance with WinDbg to see if
it's still present in memory.
