# MaskON

Microservice for **detecting and masking personally identifiable information (PII)**,
specialized in French formats (IBAN, SIREN, NIR, phone numbers…).

You send it text, it returns the same text with the PII masked plus a report of what it
found — to scrub your logs, your LLM prompts or your datasets before they leak in clear.

Serious detection rather than two homemade regexes: each type is validated by a checksum
(Luhn, mod 97, control key) to drive down false positives.

> 🚧 Work in progress.
