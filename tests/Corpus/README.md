# Offline corpus

The unit tests construct deterministic PE byte arrays in memory so the repository
does not carry executable binaries. Add only minimal, redistributable, non-secret
parser seeds here. Never add third-party drivers, crash dumps, certificates,
private keys, or malware samples.

Recommended fuzz seeds are tiny decoded forms of: a valid one-section PE32+ file,
a DOS-header-only file, a truncated optional header, an invalid directory RVA,
and overlapping section headers. Fuzz only `PeParser::ParseBytes`; do not fuzz
Windows, third-party drivers, or arbitrary kernel interfaces.

