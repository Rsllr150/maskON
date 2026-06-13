# MaskON

Microservice de **détection et masquage de données personnelles (PII)**, spécialisé sur les
formats français (IBAN, SIREN, NIR, téléphone…).

On lui envoie du texte, il renvoie le même texte avec les PII masquées et un rapport de ce
qu'il a trouvé — pour scrubber ses logs, ses prompts LLM ou ses datasets avant qu'ils ne
fuitent en clair.

Détection sérieuse plutôt que deux regex maison : chaque type est validé par checksum
(Luhn, mod 97, clé de contrôle) pour faire chuter les faux positifs.

> 🚧 Projet en cours de construction.
