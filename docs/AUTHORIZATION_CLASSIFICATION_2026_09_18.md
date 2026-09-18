# Correction de la classification d'autorisation — 18 septembre 2026

Le commit `b9f4816c0a1c6362a05e0aefd9e281e2fc4319b3` corrige la transformation
d'un constat structurel en alerte IDOR/BOLA à cause d'un nom de variable.
Les **272 tests ciblés passent**. Les **six témoins bénins** analysés après
correction ne produisent plus d'alerte, avec deux répétitions identiques.
Ce dernier résultat est une vérification de développement sur des entrées
désormais connues ; la première évaluation indépendante reste en échec.

## Défaut reproduit et correction

Avant correction, `def normalize(user_id: str): return user_id.strip()`
produisait un constat structurel « accès à un attribut sans vérification de
None ». Le moteur d'hypothèses y trouvait le texte `user_id` et en déduisait
`authorization_bypass_possible`, puis un cas `idor_bola_possible` demandant
des preuves d'authentification et de propriété de ressource. Il n'existait
pourtant aucune requête, ressource ou entrée/sortie dans cette fonction.

Les noms `owner_id` et `source_id` reproduisaient la même erreur. Le mot
`corridor` contenait aussi la sous-chaîne `idor` et déclenchait l'autre voie
de classification, même sans enrichissement par hypothèse. Un constat SQL
typé CWE-89 pouvait également devenir IDOR après enrichissement si son texte
mentionnait `user_id`.

La classification commune de
[`security_classification.py`](../belief/security_classification.py) est
maintenant utilisée par le moteur d'hypothèses et la construction des cas :

- un CWE d'autorisation explicite identifie cette famille ;
- en l'absence de CWE, une règle, un titre ou une description de scanner peut
  fournir un libellé explicite IDOR, BOLA, access control ou authorization bypass ;
- les constats structurels, temporels et de cycles ne deviennent pas des
  constats d'autorisation sur ce seul libellé ;
- le texte brut de l'extrait de code, les noms d'arguments et une sous-chaîne
  incluse dans un autre mot ne suffisent plus.

Le constat structurel initial est conservé. Les détecteurs de flux
requête → ressource et leurs CWE restent actifs. Il n'y a aucune exclusion
par projet, CVE, nom de helper tiers ou empreinte de source.
Les classifications des autres familles de vulnérabilités ne sont pas
refondues par ce changement.

## Vérifications exécutées

Les [30 nouveaux tests](../tests/test_authorization_classification.py)
couvrent le parcours complet avec et sans hypothèses sur sept noms
d'argument, les constats de scanners importés, les libellés explicites, la
préservation d'un constat SQL et deux vrais parcours requête → ressource.
Ils passent en 0,37 s, code 0. Les défauts de noms et d'extrait brut ont été
observés en échec avant la modification du code de production.

La sélection de régression suivante, qui comprend ces 30 tests, passe avec
**272 réussis en 7,39 s**, aucun test ignoré, code 0 :

```powershell
.venv\Scripts\python.exe -m pytest tests/test_authorization_classification.py tests/test_hypothesis_engine.py tests/test_audit_case.py tests/test_static_analysis_pipeline.py tests/test_guard_causality.py tests/test_dataflow.py tests/test_dataflow_causality.py tests/test_web_security_semantics.py tests/test_patch_review_profile.py tests/test_reportability_scoring.py tests/test_scan_import_tool_results.py tests/test_tool_results_mapper.py tests/test_open_source_detector_integration.py tests/test_open_source_pairs_benchmark.py -q -p no:cacheprovider --tb=short
.venv\Scripts\python.exe -m ruff check belief/security_classification.py belief/hypothesis_engine.py belief/audit_case.py tests/test_authorization_classification.py
```

Ruff rend « All checks passed », code 0. Le contrôle du diff Git passe.
La suite générale de 1868 tests du 15 septembre n'a pas été relancée : le
chiffre 272 désigne seulement les modules pertinents exécutés pour ce correctif.

Après le commit de code, depuis un checkout propre :

```powershell
.venv\Scripts\python.exe benchmark_open_source_pairs/independent-v1/evaluate_benign_controls.py --repos-root F:\belief-rd\open-source-independent-v1\repos --output F:\belief-rd\open-source-independent-v1\benign-result-b9f4816.json
```

Le pilote inchangé vérifie les empreintes des six fonctions, puis les
analyse sans les exécuter. Résultat : **6/6 sans alerte**, 6/6 déterministes,
aucune erreur d'analyse, code **0**, durée interne **0,131538 s**. Les
constats structurels éventuels restent visibles ; le témoin Praison n'a
plus de cas d'audit d'autorisation.

La [sortie complète](../benchmark_open_source_pairs/development-2026-09-18/benign-result-b9f4816.json)
conserve la révision de code analysée et le digest déterministe
`c3c4741fe7905dda4ad6b5cff3bf127951e261984e56d200ea8cca544167197b`.
Ses 9170 octets ont le SHA-256
`f6b49531b833c8bbcb58f409329faceb93a2fd3bc0cee03f84046b90853fdf89`.

## Limites conservées et suite

Le gel initial `a7c2488` et le résultat publié `676ffa5` restent inchangés :
6/24 variantes vulnérables avec correspondance fichier/ligne/type, 5/24
correctifs encore signalés, 1/24 discrimination brute, avec les problèmes
d'attribution détaillés dans
[RESULTATS.md](../benchmark_open_source_pairs/independent-v1/RESULTATS.md).
Le benchmark de 24 paires n'a pas été relancé après ce correctif ; aucune
amélioration de son score n'est revendiquée. Le résultat initial des témoins
bénins reste lui aussi publié : 5/6 sans alerte au commit de gel.

Un diagnostic additionnel avait déjà montré, avant correction, que renommer
le sélecteur `document_id` en `chosen_key` dans le petit exemple de route
supprimait le constat natif CWE-639. Le détecteur de ressource possède encore
une heuristique de nom (`_looks_resource_identifier`) ; ce défaut de
généralisation distinct n'est pas corrigé ici. Le test de non-régression
conserve deux variantes déjà reconnues, `document_id` et `resource_id`,
et ne revendique pas une invariance générale au renommage.

Les priorités suivantes restent la provenance source/sink/ligne observée
sur Penelope, la dépendance des détecteurs aux noms et la propagation des
gardes. Les seuils et résultats indépendants ne doivent pas être changés
pour faire passer ces travaux. Une nouvelle population sera nécessaire
pour une nouvelle affirmation de généralisation.

L'instantané préalable du 18 septembre à 12:16:20, heure de Paris, indiquait
47,8 Gio de RAM libres, 11 % de charge CPU et aucun processus Overwatch
détecté. Les vérifications ont quand même conservé une priorité
`BelowNormal`, deux processeurs logiques sur 32 et une exécution séquentielle.
Aucun recours au bridge Claude/Codex et aucune intervention sur le jeu ou
ses réglages.
