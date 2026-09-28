# maskON : plan de montée en niveau

## La seule chose que fait maskON

> Détecter et masquer les **identifiants français structurés**, chacun validé par
> sa **preuve** (clé de contrôle), avec des garanties mesurées.

**Hors périmètre, définitivement :** noms et adresses (NER), proxy LLM, tout ce
qui n'a pas de preuve. Ces sujets relèvent d'autres projets, qui peuvent
*utiliser* maskON.

**Règle d'or :** en cas de doute, on masque plus, jamais moins (*fail-closed*).

Les constats, avec leurs commandes de reproduction, sont dans
[`AUDIT.md`](AUDIT.md) (audit du 2026-09-28). Chaque lot y renvoie.

---

## ✅ Lot 1 : ReDoS, la faille d'abord

- [x] Corriger la regex email (et vérifier les autres détecteurs)
- [x] Un test de performance par détecteur, sur une entrée piégée
- [x] Borne de taille par requête sur l'API (413 au-delà)

## ✅ Lot 2 : une vraie bibliothèque

- [x] Un cœur **sans dépendance** ; FastAPI, uvicorn et Prometheus passent dans `maskon[api]`
- [x] API publique : `maskon.redact`, `maskon.detect`, `maskon.redact_stream`, `__all__`
- [x] `py.typed`, consommateur `mypy --strict` en CI
- [x] Version définie à un seul endroit (`maskon.__version__`)

---

## Lot 3 : ne rien laisser passer 🔴

Voir AUDIT §1, §4, §5, §9.

- [ ] Fusion : masquer **l'union** des spans qui se chevauchent ; la priorité
      ne choisit que le label (`[SIREN].contact@example.com` ne doit plus exister)
- [ ] Propriété Hypothesis : tout caractère couvert par un détecteur brut est
      masqué dans la sortie
- [ ] IBAN borné à 34 caractères, mod 97 incrémental ; retirer le `xfail`
      de `test_redos.py`
- [ ] Contrat : `redact()` ne lève **jamais** d'exception sur du texte
- [ ] `partial` par type : CB 6 premiers + 4 derniers au maximum, SIREN/NIR
      2 derniers au maximum, email première lettre + domaine
- [ ] Hash : 64 bits au moins (16 hex), clé d'au moins 16 octets, version dans
      le token (`iban_v1_…`)

**Acceptation :** chaque commande de repro de l'AUDIT (§ « Reproduire ») ne
fuit plus et ne plante plus ; ce sont des tests de non-régression ; la suite
est verte.
**Méthode :** cycle `og` (sécurité, relecture adverse utile).

## Lot 4 : contournements 🔴

Voir AUDIT §2, §3.

- [ ] Normalisation : NFKC, espaces Unicode (U+00A0, U+202F…) vers espace,
      suppression des zero-width, avec une **table d'offsets** vers le texte
      original
- [ ] Streaming : `max_len` par détecteur, `overlap` dérivé
      (`max(max_len)` + marge de contexte), jamais de coupe dans un token
- [ ] Généraliser `test_streaming_equals_batch_for_any_chunking` à un
      générateur hostile (chiffres, lettres, `@.-` et espaces)

**Acceptation :** téléphone et IBAN en NBSP masqués ; un email de 254
caractères passe en streaming sans fuite ; propriété stream == batch verte
sur le générateur hostile.
**Méthode :** cycle `og`.

## Lot 5 : une précision honnête 🟠

Voir AUDIT §6, §7, §8.

- [ ] CB : préfixes IIN (2 à 6) et longueurs par réseau
- [ ] Mots-clés de contexte (`SIREN`, `siret`, `carte`, `IBAN`, `n° sécu`…)
      qui modulent la confiance
- [ ] API publique : `min_confidence=`, `types=` / `exclude=`
- [ ] Rappel : IBAN en minuscules ou avec tirets, SIREN/NIR avec points,
      Amex 4-6-5, `+33 (0)6`, `00 33`, TVA en minuscules (une ligne de corpus
      par format)
- [ ] Précision TEL (numéros de commande pris pour des téléphones)
- [ ] Corpus **négatif** réel (logs d'accès, CSV, JSON d'API, timestamps en ms)
- [ ] README : intervalles de confiance (Wilson), pas de « 100 % » sur
      11 exemples
- [ ] Seuils de précision et de rappel par type, en gate CI
- [ ] Benchmark contre Presidio : script reproductible, même corpus, types
      communs, tableau dans le README

**Acceptation :** moins de 1 % des timestamps en ms signalés ;
`python -m scripts.evaluate` et `python -m scripts.bench_presidio` redonnent
les chiffres du README ; la CI échoue si un seuil baisse.
**Méthode :** cycle `new`.

## Lot 6 : durcissement API et CI 🟠

Voir AUDIT §10 et § « Outillage ».

- [ ] 400 (et non 500) sur un body non UTF-8
- [ ] Settings validés au démarrage (`MASKON_MAX_BYTES` invalide = refus de
      démarrer), factory `create_app(settings)`, plus de config à l'import
- [ ] `X-Request-ID` borné et validé
- [ ] `/redact/stream` dans l'histogramme de latence, métrique d'erreurs par statut
- [ ] Documenter : pas d'auth ni de rate limit (à mettre derrière une
      gateway), offsets en code points
- [ ] Lockfile, ruff étendu (`S`, `RUF`, `SIM`, `PT`, `C4`, `PL`, `N`, `D`),
      couverture de branches
- [ ] Actions épinglées par SHA, bloc `permissions:`, `needs: test` sur le
      job `package`
- [ ] Dependabot, `pip-audit`, build et scan Docker (Trivy) en CI, pre-commit
- [ ] Dockerfile : base épinglée par digest, multi-stage, `--proxy-headers`

**Méthode :** Claude en direct.

## Lot 7 : release engineering 🟠

- [ ] **Licence (décision humaine) :** AGPL-3.0 (protège, mais freine
      l'adoption en entreprise) **ou** MIT / Apache-2.0 (maximise l'adoption)
- [ ] `CHANGELOG.md` (Keep a Changelog) et politique semver écrite
- [ ] `SECURITY.md` : comment signaler une PII qui passe au travers, plus une
      issue template « PII non détectée »
- [ ] `CONTRIBUTING.md` : ajouter un détecteur = forme + preuve + tests + corpus
- [ ] Publication PyPI par GitHub Actions en *trusted publishing* (aucun token stocké)

**Acceptation :** le tag `v0.2.0` publie sur TestPyPI, puis sur PyPI ;
`pip install maskon` du README devient vrai.
**Méthode :** Claude en direct.

## Lot 8 : garanties écrites, adoption, dette 🟢

- [ ] `docs/guarantees.md` : pour chaque type, le format accepté, la preuve,
      ce qui **n'est pas** détecté, les faux négatifs mesurés
- [ ] Modèle de menace : entrée non fiable, taille, encodage, contournements
      connus (homoglyphes)
- [ ] CLI : `maskon redact < app.log > clean.log`
- [ ] `maskon.logging.RedactingFilter`, à brancher en une ligne
- [ ] API : `Finding` gelé (`frozen=True, slots=True`), type en `StrEnum`
      exporté, instance par défaut en cache
- [ ] Dette : l'égalité NIR/CB sur 15 chiffres dépend encore de l'ordre des
      détecteurs
- [ ] Dette : docstrings périmées (`luhn.py:4`, `redaction.py:5`)
- [ ] Dette : `SpiDetector._is_valid` accepte un groupement mélangé que
      `detect` refuse
- [ ] Dette : `\s?` après `+33` dans TEL, incohérent avec `[ .-]`
- [ ] Nouveaux types, seulement avec preuve : carte d'identité (ancien format,
      clé de contrôle). Toujours : un détecteur + ses tests + des lignes de
      corpus + une ligne de README

---

## Définition de « niveau senior »

- [x] `pip install .` sans dépendance, typé, API en quelques fonctions
- [x] Aucune regex super-linéaire, prouvé par des tests
- [ ] Rien de détecté ne sort en clair, prouvé par une propriété (lot 3)
- [ ] Aucune entrée ne fait planter `redact()` (lot 3)
- [ ] Chaque chiffre du README est reproductible par une commande et tient
      hors du corpus maison (lot 5)
- [ ] Ce que l'outil **ne** fait **pas** est écrit (lot 8)
- [ ] Publié, versionné, avec un changelog et une adresse pour signaler une faille (lot 7)
