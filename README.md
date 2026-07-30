# TRANCE
### A Forensic Artifact Triage Tool for Tor Browser Activity

TRANCE is an automated digital-forensics tool that reconstructs Tor Browser 
usage on Windows 10/11 systems by acquiring, parsing, and correlating evidence 
across registry, disk, and memory artifacts — the three layers most likely to 
survive Tor Browser's privacy-preserving design.

Existing general-purpose forensic suites (EnCase, FTK, AXIOM) provide broad 
file-system and registry browsing but encode no Tor-specific knowledge, leaving 
examiners to manually correlate scattered artifacts by hand. TRANCE closes that 
gap with three automated modules — registry & execution evidence, disk & 
database artifacts, and memory analysis (Volatility 3 + custom YARA signatures) 
— unified by a shared SHA-256 hashing and chain-of-custody layer, and merged 
into a single reproducible HTML/JSON report.

Built as a CS3400 Cyber Security coursework project, evaluated against 
synthetic ground-truth data across live, shutdown, and hibernation capture 
scenarios.

**Status:** In development · **Platform:** Windows 10/11 (target) · 
