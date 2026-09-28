# Audit maskON (28/09/2026)

Branche `bench/wave-usage`, commit `ce773c5`. J'ai lu tout le code (`maskon/`, `scripts/`, CI, Docker), lancé les gates, puis essayé de casser le moteur avec des entrées réelles et du fuzzing. Tous les constats ci-dessous se reproduisent avec les commandes indiquées.

> **Instantané daté, à ne pas mettre à jour.** C'est la preuve de l'état au commit `ce773c5`. Le plan d'action vivant est dans [`PLAN.md`](PLAN.md), dont les lots renvoient aux sections (§) ci-dessous.

---

## Verdict

**L'ingénierie est au-dessus de la moyenne. Le produit n'est pas encore fiable.**

L'hygiène est très bonne : cœur pur sans dépendance, mypy strict, 339 tests, 99 % de couverture, Hypothesis, garde ReDoS, et un README honnête sur ses limites. Peu de projets perso en sont là.

Mais le rôle d'un outil de masquage, c'est de **ne jamais laisser passer une PII qu'il a vue**, et d'**annoncer des chiffres qui tiennent hors de son propre corpus**. Sur ces deux points, maskON échoue aujourd'hui :

- il y a **3 chemins où l'outil laisse passer (*fail-open*)** : la fusion des spans, le streaming et les espaces Unicode ;
- une **entrée utilisateur fait planter** `redact()` (et renvoie un 500 côté API) ;
- une **confiance de 1.0 est affichée sur des détections qui sont fausses dans ~90 % des cas** sur des nombres quelconques.

| Axe | Note | Commentaire |
|---|---|---|
| Architecture / lisibilité | 8/10 | Couches propres, code court et clair |
| Qualité outillage | 7/10 | Gates solides, mais ruff minimal et CI non durcie |
| Tests | 6/10 | Couverture forte, mais invariants prouvés sur des générateurs trop gentils |
| **Sûreté du masquage** | **3/10** | Plusieurs fuites démontrées ci-dessous |
| Qualité de détection mesurée | 4/10 | Corpus synthétique de 99 lignes, écrit par l'auteur |
| Release / projet « réel » | 3/10 | Pas publié, pas de tag, pas de CHANGELOG ni de SECURITY |

**Note globale : 5,5/10.** Pour passer à 8, il faut corriger la section 🔴 d'abord. Il n'y a presque rien à ajouter pour ça, surtout à rendre ce qui existe *fail-closed*.

---

## 🔴 Bloquants : l'outil laisse passer des PII ou plante

### 1. La fusion des chevauchements est *fail-open*

`service/merge.py` garde le meilleur finding et **jette le perdant en entier**. Les caractères du perdant qui ne sont pas couverts par le gagnant restent donc en clair.

```python
>>> maskon.redact("443061841.contact@example.com")
'[SIREN].contact@example.com'          # l'email est détecté, puis relâché
>>> maskon.redact("06 12 34 56 78jean@example.com")
'06 12 34 56 [EMAIL]'                  # 8 chiffres du téléphone en clair
```

Sur 60 000 textes aléatoires faits de fragments de PII, j'ai trouvé **658 cas** où un caractère détecté par un détecteur ressort en clair.

**Correctif :** masquer **l'union** des spans qui se chevauchent, et ne choisir que le *label* par la règle de priorité. En cas de doute, on masque plus, jamais moins. Ajouter la propriété Hypothesis suivante : *tout caractère couvert par un détecteur brut est masqué dans la sortie*.

### 2. Le streaming fuit, et l'invariant « stream == batch » est faux

- `DEFAULT_OVERLAP = 64`, alors qu'un email fait légalement jusqu'à 254 caractères. Avec une partie locale de 80 caractères, le début de l'email sort en clair : `aaaaaaaaaaaaaaaaaaaaaaaa[EMAIL]`.
- Avec un fuzz sur des fragments collés, le stream diffère du batch dans **~1 cas sur 3**, et dans **246 cas sur 5 000** il **laisse passer plus de PII que le batch**. La coupe perd le contexte à gauche (`\b` et `(?<!\d)`). Résultat : sur-masquage d'un côté, fuite de l'autre.
- Le test `test_streaming_equals_batch_for_any_chunking` passe uniquement parce que son générateur **ne contient ni chiffre ni `@` dans le remplissage**. On prouve l'invariant sur les seules entrées qui ne peuvent pas le casser.

**Correctif :**

- borner chaque détecteur à une longueur maximale connue (`max_len` par détecteur), puis calculer `overlap = max(max_len) + marge de contexte` ;
- ne jamais couper à l'intérieur d'un « token » (une suite de caractères non séparateurs) ;
- généraliser le test de propriété à `st.text()` avec un alphabet chiffres/lettres/`@.- `.

### 3. Les espaces insécables contournent tous les formats groupés

La typographie française utilise U+00A0 et U+202F comme séparateurs de milliers. Word, les PDF et les CRM en produisent sans arrêt.

```python
>>> maskon.redact("06 12 34 56 78")   # rien n'est masqué
>>> maskon.redact("FR76 3000 6000 0112 3456 7890 189")  # rien
>>> maskon.redact("jean​@example.com")                # zero-width : rien
```

Pour un outil spécialisé *français*, c'est le contournement numéro un. Le PLAN (lot 5) le cite comme « contournement connu », mais il n'est ni corrigé ni documenté dans le README.

**Correctif :** une passe de normalisation (NFKC, espaces Unicode vers espace, suppression des zero-width), avec une **table de correspondance des offsets** vers le texte original.

### 4. Crash sur entrée utilisateur (DoS applicatif)

```python
>>> maskon.redact("FR76 " + "1234 " * 1200)
ValueError: Exceeds the limit (4300 digits) for integer string conversion
```

La regex IBAN n'a pas de borne (`(?: [A-Z0-9]{4})+`) et `mod97` fait `int()` sur toute la chaîne. Le cas est « épinglé » en `xfail(strict=True)` dans `test_redos.py` : c'est honnête, mais **un crash connu déclenchable par l'utilisateur ne se documente pas, il se corrige**. Même souci pour le coût quadratique du `int()` sur de grands nombres.

**Correctif :** un IBAN fait au plus 34 caractères, donc borner la regex à `{1,8}` groupes. Calculer le mod 97 de façon incrémentale (par blocs de 9 chiffres). Enfin, un contrat clair : `redact()` ne lève **jamais** d'exception sur du texte.

### 5. Le mode `partial` ne masque presque rien

`partial` garde toujours les 4 premiers et les 3 derniers caractères, quel que soit le type :

| Valeur | Sortie | Ce qui fuit |
|---|---|---|
| SIREN `732829320` | `7328****320` | **7 chiffres sur 9**. Avec la clé Luhn, il ne reste qu'environ 10 candidats. |
| TEL `0612345678` | `0612****678` | 7 chiffres sur 10 |
| Email | `jean****com` | le prénom |

C'est réversible en pratique. **Correctif :** une règle par type (PCI-DSS pour la CB : 6 premiers + 4 derniers au maximum ; SIREN/NIR : rien, ou seulement les 2 derniers ; email : première lettre + domaine), et un seuil minimal de caractères masqués.

---

## 🟠 Majeurs : les chiffres annoncés ne tiennent pas

### 6. « Validé par checksum » ne veut pas dire « c'est une PII »

Luhn laisse passer **1 nombre aléatoire sur 10**. Mesuré sur 20 000 tirages :

| Entrée | Signalée comme PII |
|---|---|
| nombre quelconque de 9 chiffres | 9,9 % (SIREN) |
| 13 à 19 chiffres | ~10 % (CB) |
| **timestamp en ms** (`1727517600123`) | **10,1 %** (CB) |

Exemple : `req=443061841 took 12ms` devient `req=[SIREN] took 12ms`.

Le cas d'usage n°1 annoncé est **le nettoyage de logs**, qui sont pleins de timestamps en ms et d'identifiants numériques. Chacun de ces faux positifs sort pourtant avec `confidence: 1.0`. La confiance n'est donc pas calibrée : c'est un a priori codé en dur.

**À faire :**

- CB : vérifier les préfixes IIN (2 à 6) et les longueurs par réseau. Ça élimine déjà une grosse part des faux positifs.
- Des **mots-clés de contexte** (`SIREN`, `siret`, `carte`, `IBAN`, `n° sécu`…) qui modulent la confiance.
- Un paramètre public `min_confidence=` et un paramètre `types=` / `exclude=`.
- Une confiance qui reflète P(PII | match), et non « un checksum est passé ».

### 7. L'évaluation est circulaire

- 99 exemples **synthétiques**, écrits par la même personne que les regex. Afficher 100 % de précision sur un corpus qu'on a construit soi-même, c'est de la non-régression, pas une mesure.
- Il n'y a **aucun corpus négatif** (de vrais logs sans PII). Or c'est exactement là que les faux positifs du point 6 apparaîtraient.
- Les supports sont minuscules (CB : 11, PASSEPORT : 2, IMMAT : 3). Pour 11/11, l'intervalle de Wilson à 95 % va de **74 % à 100 %**. Le README devrait donner des intervalles, pas « 100 % ».
- Les scores ne sont **pas un gate CI** : une régression de rappel passe sans bruit.

**À faire :** un jeu négatif réaliste (logs d'accès, CSV, JSON d'API), des intervalles de confiance, un seuil minimal par type dans la CI, et le benchmark contre Presidio (lot 6 du PLAN).

### 8. Rappel : des formats courants manqués

Tous ces cas ont été testés, et tous passent en clair :

| Type | Format manqué |
|---|---|
| IBAN | minuscules, tirets (`FR76-3000-…`) |
| SIREN | points (`732.829.320`) |
| NIR | points ou tirets (`1.85.05.78.006.084.xx`) |
| CB | Amex 4-6-5 (`3782 822463 10005`), points |
| TEL | `+33 (0)6 12 34 56 78`, `00 33 6 12 …`, chiffres pleine chasse |
| TVA | minuscules (`fr40303265045`) |
| EMAIL | domaines IDN (`exämple.fr`) |

Chacun de ces formats devrait avoir une ligne de corpus.

### 9. Le hash est tronqué à 32 bits

`digest[:8]` donne 32 bits. Le paradoxe des anniversaires donne ~50 % de collision vers 77 000 valeurs, et j'ai mesuré **5 collisions sur 200 000 téléphones**. Or ce mode est vendu pour « corréler des données sans les révéler » : des collisions **corrompent** justement cette corrélation.

Autres problèmes :

- aucune longueur minimale de clé (`hash_key=b"a"` est accepté) ;
- pas de version de clé dans le token, donc aucune rotation possible.

**À faire :** au moins 64 bits (16 hex), une clé d'au moins 16 octets, et un préfixe de version (`iban_v1_…`).

### 10. API HTTP

| Problème | Constat |
|---|---|
| Body non UTF-8 sur `/redact/stream` | **500** (`UnicodeDecodeError` non gérée) au lieu de 400 |
| `MASKON_MAX_BYTES=1MB` | **500 sur toutes les requêtes**, `/health` compris. La config est lue à chaque requête au lieu d'être validée au démarrage. |
| `X-Request-ID` | Reprise sans limite ni validation dans les logs et la réponse (testé avec 5 000 caractères) |
| Config à l'import | `service = RedactionService()` et `configure_logging()` s'exécutent à l'import du module. C'est contraire au commit `9188f5d` (« no import-time config »). Il faut une factory `create_app(settings)`. |
| Sécurité | Pas d'authentification, pas de rate limit, `/docs`, `/openapi.json` et `/metrics` publics. C'est acceptable derrière une gateway, mais il faut **l'écrire**. |
| Offsets | En *code points* Python. Un client JS (UTF-16) se décale dès le premier emoji. À documenter, ou à proposer en option. |
| Observabilité | `/redact/stream` n'est pas dans l'histogramme de latence. Il n'y a pas de métrique d'erreurs par statut. |

---

## 🟡 Qualité de code et API publique

- **`Finding` est mutable** (`@dataclass` sans `frozen=True, slots=True`) alors que c'est un type public semver. `type: str` devrait être un `Literal` ou un `StrEnum` exporté.
- **L'API n'est pas extensible** : impossible d'ajouter un détecteur maison ou de choisir les types via l'API publique. `Detector` est interne.
- `maskon.detect()` reconstruit un `RedactionService` et relit l'environnement **à chaque appel**. Une instance par défaut en cache, ou un objet public `Redactor`, ferait mieux.
- La détection fait 11 passes regex complètes sur le texte. Ça passe à 10 MB/s, mais une alternation compilée ou un pré-filtre sur les chiffres ferait mieux sur de gros volumes.
- `TEL` accepte `\s?` après `+33`, donc aussi un retour à la ligne ou un NBSP, alors que les autres séparateurs sont `[ .-]`. C'est incohérent.
- Des docstrings sont périmées : `redaction.py:5` (« Masking will be wired in later »), `luhn.py:4` (« later, bank card »). Elles sont déjà listées dans le PLAN, mais toujours pas corrigées.
- `SpiDetector._is_valid` accepte des groupements que `detect` refuse (PLAN, lot 7). La dette connue reste ouverte.

---

## 🟡 Outillage, CI, packaging

| Manque | Pourquoi c'est important |
|---|---|
| **Ruff minimal** (`E,F,I,UP,B`) | Ajouter au moins `S` (bandit), `RUF`, `SIM`, `PT`, `C4`, `PL`, `N`, `D` (docstrings sur l'API publique) |
| **Pas de lockfile** (`uv.lock` / `requirements.lock`) | Le build Docker et la CI ne sont pas reproductibles |
| Actions non épinglées par SHA, pas de bloc `permissions:` | Risque supply chain de base (moindre privilège) |
| Pas de Dependabot, `pip-audit` ni CodeQL | Rien ne surveille les dépendances |
| Pas de pre-commit | Les gates ne tournent qu'en CI |
| **Docker absent de la CI** | L'image n'est ni construite, ni testée, ni scannée (Trivy) |
| Dockerfile | Base non épinglée par digest, un seul stage, pas de `--proxy-headers`, un seul worker sans doc |
| Tests ReDoS basés sur le temps | Ils risquent d'être instables sur les runners partagés. Mieux vaut compter les pas (ou borner les regex), ou les isoler dans un job dédié. |
| Job `package` indépendant de `test` | Ajouter `needs: test` |
| Pas de couverture de branches | Ajouter `branch = true` : 99 % en lignes cache peut-être des `if` jamais faux |
| Pas de tests de mutation (`mutmut`) | Sur des validateurs de checksum, c'est le seul moyen de savoir si les tests *mordent* |

---

## 🟡 Ce qui manque pour que ce soit un vrai projet

1. **Publication.** Le README dit `pip install maskon`, mais le paquet **n'est pas sur PyPI** : c'est faux aujourd'hui. Il faut un workflow de release en *trusted publishing* sur tag.
2. **Versioning.** Il y a eu un commit `feat!:` (breaking), mais la version est toujours `0.1.0` et il n'y a **aucun tag git**.
3. **`CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`** : tous absents. Pour un outil de sécurité, `SECURITY.md` n'est pas optionnel. Il faut aussi une issue template « PII non détectée ».
4. **`docs/guarantees.md`** : pour chaque type, le format accepté, la preuve, ce qui n'est **pas** détecté, et le modèle de menace. Aujourd'hui, les limites sont éparpillées dans le README.
5. **Licence.** L'AGPL-3.0 sur une *bibliothèque* destinée aux entreprises (logs, prompts LLM) bloque l'adoption. La décision est ouverte dans le PLAN (lot 3) : il faut la trancher.
6. **Un CLI** : `maskon redact < app.log > clean.log`. C'est l'usage évident pour les logs, et il manque.
7. **`PLAN.md`** n'est pas versionné et n'est pas à jour : les lots 1 et 2 sont faits mais non cochés. Il est en français alors que tout le reste est en anglais. Il faut le committer (ou le passer en issues GitHub) et choisir une langue.
8. **Intégrations** : un `logging.Filter` prêt à l'emploi (`maskon.logging.RedactingFilter`) ferait de maskON un outil qu'on branche en une ligne. C'est le meilleur levier d'adoption pour le cas « logs ».

---

## ✅ Ce qui est vraiment bien (à garder)

- La règle « forme + preuve » est claire, et chaque détecteur fait moins de 30 lignes.
- Le cœur est **sans dépendance** et vérifié par un consommateur `mypy --strict` sur la wheel installée seule. C'est rare, et c'est exactement ce qu'il faut.
- La culture de la mesure : benchmark, calibration, faux positifs affichés, et le bug O(n²) trouvé par le benchmark.
- La conscience ReDoS : l'email linéaire est prouvé équivalent par Hypothesis.
- Pas de clé de hash par défaut, et une erreur explicite. Bonne décision de sécurité.
- Le corps de requête est limité en streaming, sans bufferiser au-delà.
- Les messages de commit conventionnels, et le README qui écrit ses propres limites.

---

## Plan d'action priorisé

| # | Action | Effort | Impact |
|---|---|---|---|
| 1 | Fusion en **union** des spans + propriété « rien de détecté ne sort en clair » | S | 🔴 fuite |
| 2 | Borner l'IBAN, mod 97 incrémental, `redact()` ne lève jamais d'exception | S | 🔴 crash |
| 3 | Normalisation Unicode (NBSP, NNBSP, zero-width) avec table d'offsets | M | 🔴 contournement |
| 4 | Streaming : `max_len` par détecteur, overlap dérivé, coupe hors token, propriété sur `st.text()` | M | 🔴 fuite |
| 5 | `partial` par type, hash sur 64 bits, clé d'au moins 16 octets, version dans le token | S | 🔴/🟠 |
| 6 | Préfixes IIN pour la CB, mots-clés de contexte, `min_confidence` / `types` publics | M | 🟠 précision |
| 7 | Corpus négatif réel, intervalles de confiance, seuils de rappel/précision en CI | M | 🟠 crédibilité |
| 8 | API : 400 sur UTF-8 invalide, settings validés au démarrage, `create_app()`, `X-Request-ID` borné | S | 🟠 |
| 9 | Lockfile, ruff étendu, actions épinglées, `permissions:`, pip-audit, build Docker en CI | S | 🟡 |
| 10 | Tag `v0.2.0`, CHANGELOG, SECURITY, CONTRIBUTING, publication PyPI, décision de licence | S | 🟡 projet réel |
| 11 | CLI + `logging.Filter` | S | 🟡 adoption |

Les points 1, 2 et 5 prennent une demi-journée et suppriment les fuites les plus graves. Il faut commencer par eux.

---

## Reproduire les constats

```bash
source .venv/bin/activate
python -c "import maskon; print(maskon.redact('443061841.contact@example.com'))"   # fusion fail-open
python -c "import maskon; print(maskon.redact('06 12 34 56 78'))"  # NBSP
python -c "import maskon; maskon.redact('FR76 ' + '1234 ' * 1200)"                  # crash
python -c "import maskon; print(maskon.redact('732829320', mask='partial'))"        # partial
python -c "import maskon; print(maskon.redact('ts=1727517600123 req=443061841'))"   # faux positifs
python -c "import maskon; print(''.join(maskon.redact_stream(['a'*80+'@example.com'][0][i:i+7] for i in range(0,92,7))))"  # stream
```
