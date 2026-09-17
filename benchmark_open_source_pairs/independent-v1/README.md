# Corpus public de 24 projets distincts, independent-v1

Ce corpus est qualifié les 16–17 septembre 2026 avant toute mesure du détecteur.
Le détecteur et le moteur de paires restent ceux du commit
`83c65692239a85435cb8f17c0eb9a8cc951a1d9b`. Les résultats seront publiés
séparément dans `RESULTATS.md` après le commit de gel des entrées.

## Contenu et limites

- 24 projets, une paire parent/correctif par projet : 48 versions, chacune
  analysée deux fois par le moteur existant.
- 27 fichiers présentés au détecteur. La qualification lie 37 fichiers : dix
  dépendances supplémentaires servent à vérifier les correctifs par lecture.
  Elles ne sont pas toutes présentes dans les instantanés d'analyse. Cette
  limite de contexte peut provoquer des alertes sur des appels pourtant
  validés ailleurs ; le résultat doit la conserver et l'expliquer.
  Le moteur v1 exige notamment que chaque fichier analysé change entre les
  révisions : l'appelant d'écriture Dulwich, inchangé, reste du contexte de
  qualification. Le moteur de paires n'a pas été modifié pour ce corpus.
- 22 mécanismes de chemin/fichier et deux mécanismes SQL. Les chemins de
  proxy HTTP, références HDF5 et constructions de littéraux SQL restent dans
  le dénominateur même si le détecteur ne reconnaît pas ces opérations.
- Six témoins de fonctions pures, analysés séparément deux fois chacun. Ils
  ne représentent ni six projets supplémentaires ni la précision générale.
- Aucun code tiers importé, installé ou exécuté ; aucun service lancé. Les
  tests amont sont recensés comme indices de patch, jamais présentés comme
  des tests que nous avons exécutés.

`qualification.json` décrit pour chaque paire le flux concerné, le contrôle
réel et ses hypothèses. Les contrôles sont limités au mécanisme nommé : les
racines, paramètres de configuration, règles POSIX, absence de liens hostiles
ou stabilité du système de fichiers sont explicites selon le cas. Le témoin
datamodel-code-generator suppose notamment `allow_remote_refs=False`.

Les plages de score sont fixées avant mesure. Le moteur v1 n'accepte qu'une
plage commune aux deux versions par fichier ; le déplacement du contrôle
Penelope impose une plage plus large. Une alerte dans cette plage reste une
mesure localisée par fichier/ligne/type, pas une preuve d'exploitation ni une
attribution sémantique certaine au CVE. Les constats hors cible restent dans
les résultats bruts.

L'avis global Snowflake est classé CWE-73 par sa source. Ce libellé est
conservé ; la catégorie de détecteur SQL vient de notre lecture du mécanisme
`LiteralOption`, également décrit dans l'avis. Les correctifs des autres
mécanismes de cet avis ne sont pas confondus avec cette paire.

Les identifiants `LicenseRef-*` désignent les textes amont précisément liés
par chemin et empreinte, sans leur attribuer une licence standard différente.
Le corpus publie des métadonnées et des empreintes ; les sources tierces
complètes restent dans le cache Git externe.

## Sélection vérifiable

[PROTOCOL.md](PROTOCOL.md) fixe les règles. [selection.json](selection.json)
conserve les 300 avis uniques issus de trois pages de l'API GitHub, les URL
des requêtes, dates, empreintes et décisions. Le paramètre initial `page`
répétait la première page : les doublons ont été détectés puis remplacés par
la pagination `Link` à curseur. Ils ne sont pas comptés.

[project-exclusions.json](project-exclusions.json) contient les empreintes de
253 identités déjà présentes dans les populations locales SusVibes/PatchEval,
les caches de recherche et le corpus historique de trois projets. Les noms
de projets réservés n'ont servi qu'à l'exclusion ; leurs cas, correctifs,
étiquettes et résultats n'ont pas été consultés. Les anciens et nouveaux
noms d'un dépôt sont comparés lorsqu'un renommage est identifié.

Cette séparation de projets n'établit pas leur absence du préentraînement
des modèles, de tout échange antérieur ou d'Internet. L'échantillon est
public, choisi sur avis et localisé par les correctifs, sans tirage aléatoire.

Quatre candidats récents restent exclus ou non résolus : le contrôle SQL
Langroid, son autre contrôle de fichiers, le correctif de requêtes Anki et
le contrôle des liens BBOT. Le mécanisme Shamefile est en Rust. Les motifs
précis figurent dans la sélection. Les alertes du détecteur n'ont pas servi
à ces décisions.

## Vérification et exécution

Le dépôt BELIEF doit être propre et le corpus commité avant l'exécution.
Le répertoire des sources contient des dépôts Git sans checkout, nommés
selon `checkout_dir`. Chaque dépôt doit contenir les commits, parents,
licences et blobs liés. L'acquisition Git HTTPS est séparée de la mesure ;
le moteur refuse le réseau et le chargement implicite de blobs pendant celle-ci.

Depuis la racine BELIEF, avec un nouveau chemin de sortie externe au dépôt :

```powershell
.venv\Scripts\python.exe scripts\run_open_source_pairs_benchmark.py --manifest benchmark_open_source_pairs\independent-v1\cases.json --repos-root F:\belief-rd\open-source-independent-v1\repos --output F:\belief-rd\open-source-independent-v1\pair-result.json
.venv\Scripts\python.exe benchmark_open_source_pairs\independent-v1\evaluate_benign_controls.py --repos-root F:\belief-rd\open-source-independent-v1\repos --output F:\belief-rd\open-source-independent-v1\benign-result.json
```

Les sorties sont créées sans écrasement. Une analyse de paires terminée avec
un seuil échoué rend le code 1 ; ce résultat doit être conservé. Les seuils
sont inchangés : rappel ≥ 0,5, alertes sur correctifs ≤ 0,2, discrimination
≥ 0,4, répétition déterministe = 1 et aucune erreur d'analyse.

Après cette première mesure, le corpus devient une preuve de développement.
Tout ajustement du détecteur doit être évalué ensuite sur une nouvelle
population de projets pour soutenir une nouvelle généralisation. Le corpus
historique de trois projets et ses résultats échoués restent inchangés.
