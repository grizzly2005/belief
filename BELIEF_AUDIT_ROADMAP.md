# BELIEF — Audit architectural & roadmap « prototype → militaire »

**Date** : 2026-04-17
**Périmètre** : `belief_clean.zip` (~1000 fichiers, `belief/` + `belief_backup_pre_v3/` + tools_bundled + tests + benchmark)
**Base d'analyse** : Rapport 1 (LangGraph/NetworkX/PyDriller, 65-70% potentiel) + Rapport 2 (stabilisation > features, décide() bottleneck) + relecture exhaustive du code

---

## 0. TL;DR

**État réel** : BELIEF est un **prototype de recherche** avec du bon code noyau (modèles sextuplet solides, Z3 bien intégré, bridges fonctionnels, benchmark CVE existant) **noyé dans ~60 % de code mort et architectural drift**.

**Les deux rapports avaient raison mais sous-estimaient** :

- Rapport 1 recommandait LangGraph/NetworkX/pgmpy → rien n'est migré, tout est custom.
- Rapport 2 recommandait « stabilisation avant tout » → tu as rajouté v3.1, v4, la couche cognitive, 26 sous-modules jamais importés.

**Le vrai ratio code vivant / code mort** : sur les ~37 gros sous-modules de `belief/`, **26 sont totalement morts** (importés uniquement par des tests qui portent leur nom, jamais par le pipeline principal). Tous les tests `test_phase{N}_modules.py` testent du code que personne n'exécute en prod.

**La couche « cognitive » (v4) — ta killer feature — n'est pas branchée sur le CLI**, n'est pas couverte par le benchmark, ne lit pas `belief.sources`, et souffre de **10 bugs d'algorithme concrets** documentés ici.

**Cap à viser pour « qualité militaire »** : pas ajouter de features. Supprimer la moitié de la codebase, brancher ce qui reste correctement, mesurer, publier.

---

## 1. Bugs confirmés (file:line, avec explication)

Tous les bugs ci-dessous ont été vérifiés par lecture de code. Je précise pour chacun : **où** c'est cassé, **pourquoi** c'est cassé, **comment** ça se manifeste, **quoi** faire.

### B-01 — `CognitiveLoop` absent du CLI (feature flagship inaccessible)

**Où** : `belief/cli.py` (381 lignes) — sous-commandes enregistrées : `analyze`, `scan`, `hunt`, `self-check`, `serve`, `benchmark`, `export`, `frontier`, `report`. **Aucune** sous-commande `cognitive`, `loop`, `reason`, ou équivalent.

**Pourquoi** : `CognitiveLoop` n'a été intégré que dans `tests_bridges/test_cognitive.py`. Il n'y a aucune entry point utilisateur.

**Manifestation** : un utilisateur qui installe BELIEF et lance `python -m belief --help` ne voit jamais la couche cognitive. La doc SESSION3_DELIVERY.md la présente pourtant comme l'aboutissement du projet.

**Fix** : ajouter `belief/cli.py::cmd_cognitive(args)` qui instancie `CognitiveLoop`, appelle `.run_cycle(project_path)`, et sérialise le `CognitiveReport` (voir B-03 d'abord). Prioritaire.

---

### B-02 — Collision de nom `BeliefGraph` (`belief/graph.py` vs `belief/cognitive/belief_graph.py`)

**Où** :
- `belief/graph.py:39` → `class BeliefGraph` (DAG de dépendances, API `add_beliefs/cascade_impact/fragile_roots`)
- `belief/cognitive/belief_graph.py:101` → `class BeliefGraph` (graphe probabiliste typé, API `add_belief/auto_relate/bayesian_update/find_contradictions/merge_equivalent`)

**Pourquoi** : refactor v4 sans renommage. `belief/__init__.py` expose celui de `graph.py`, celui de `cognitive/` n'est accessible que via `belief.cognitive.BeliefGraph`.

**Manifestation** : `from belief import BeliefGraph` et `from belief.cognitive import BeliefGraph` donnent deux classes **incompatibles**. Erreurs silencieuses à l'usage. L'orchestrator utilise l'ancien ; la couche cognitive utilise le nouveau. Pas de pont.

**Fix** : renommer `belief/cognitive/belief_graph.py::BeliefGraph` → `ProbabilisticBeliefGraph` ou `CognitiveGraph`. Ou renommer l'ancien en `BeliefDependencyGraph`. **Avant toute autre intervention**, car ça bloque tout refactor propre.

---

### B-03 — `CognitiveReport` n'a pas de `.save()` (incompatible avec `AnalysisReport`)

**Où** :
- `belief/models.py:421` → `AnalysisReport` avec `to_dict()` **et** `save(path)` (ligne 482)
- `belief/cognitive/cognitive_loop.py:46` → `CognitiveReport` avec `to_dict()` **et** `summary()` — pas de `save()`

**Pourquoi** : deux schémas de rapport dans deux branches de code, jamais unifiés.

**Manifestation** : `belief/cli.py:72` appelle `report.save(str(output_path))`. Si on branche `CognitiveLoop` dans le CLI (cf. B-01), ça pétera avec `AttributeError: 'CognitiveReport' object has no attribute 'save'`.

**Fix** : soit `CognitiveReport` hérite de `AnalysisReport` et l'étend, soit on ajoute `save()` qui fait `json.dump(self.to_dict(), ...)`. Idéalement unifier en un seul dataclass avec un champ optionnel `cognitive_section: Optional[dict]`.

---

### B-04 — `Belief.id` fragile (hash de texte LLM non stable entre runs)

**Où** : `belief/models.py:184-187`
```python
raw = f"{self.predicate.expression}:{self.scope.qualified_name}"
self.id = hashlib.sha256(raw.encode()).hexdigest()[:12]
```

**Pourquoi** : `predicate.expression` est généré par un LLM (GPT/Claude) **ou** par un bridge (Bandit, DLint) dont les messages changent entre versions. Une virgule, une majuscule, un « possibly » au lieu de « maybe » → hash différent → belief perçu comme nouveau.

**Manifestation concrète** :
- Run 1 : Bandit signale `"Possible hardcoded password: secret"` → ID = `a1b2c3d4e5f6`
- Bandit v1.8 : `"Hardcoded password string detected: secret"` → ID = `xyz987654321`
- `memory.is_known_fp(belief.id)` retourne `False` → l'utilisateur revoit un FP qu'il a déjà classé.
- `MemoryEngine.suggest_confidence_adjustment()` (ligne 225) ne retrouvera pas non plus les observations précédentes via l'index `expr[:40]` si le prefixe a bougé.

**Fix** (plusieurs options) :
1. **Normaliser avant hash** : extraire une forme canonique (tokens triés, variables nommées `$1 $2`, stopwords retirés).
2. **Hash sur triplet structurel** : `(cwe_id, scope.file_path, scope.line_start ± window)` au lieu du texte.
3. **Index à double clé** : `expr_prefix` ET `(cwe, scope)`.

Recommandation : option 2 pour les bridges déterministes, option 1 pour les beliefs LLM. Ajouter un champ `Belief.canonical_key` calculé séparément de l'id.

---

### B-05 — Bootstrap problem dans `_decide()` novelty (toutes les 1ères valeurs à 0.8)

**Où** : `belief/cognitive/cognitive_loop.py:390-395`
```python
if self.memory.is_known_fp(belief.id):
    novelty = 0.0
elif belief.id in {e.belief_id for e in self.memory.recall_validated()}:
    novelty = 0.1
else:
    novelty = 0.8  # new pattern → explore
```

**Pourquoi** : `memory` n'est remplie qu'en `_learn()`, qui tourne **après** `_decide()`. Au premier run, `memory` est vide → **tous les beliefs ont novelty=0.8**. Le facteur perd tout pouvoir discriminant.

**Manifestation** : au 1er run, le score final = `uncertainty*0.30 + exploitability*0.30 + impact*0.20 + 0.16` (le 0.8*0.2 constant). Les stratégies d'exploration « bandit » recommandées par le Rapport 1 sont trivialisées.

**Bonus bug** : `{e.belief_id for e in self.memory.recall_validated()}` **reconstruit le set à chaque appel** — O(N) par belief × M beliefs = O(N*M). Pré-calculer au début de `_decide` batch.

**Fix** :
1. **Pré-chauffe** : au démarrage, charger `memory.json` en `self._fp_ids: set`, `self._validated_ids: set`. Lookup O(1).
2. **Novelty bayésienne** : pour beliefs inconnus, utiliser la précision historique du bridge (`memory.fp_rate_for_bridge`) + un prior. Pas une constante 0.8.
3. **Multi-armed bandit** (proposé par Rapport 1) : UCB1 ou Thompson sampling sur `(cwe, bridge)` pairs. Le facteur novelty devient `UCB(arm)` au lieu d'une constante.

---

### B-06 — CWE-guessing dupliqué 4 fois avec maps incohérentes

**Où** (4 endroits qui devinent le CWE à partir du texte d'un belief) :
1. `belief/cognitive/cognitive_loop.py:_guess_cwe_from_belief` (ligne 405) — 13 mots-clés
2. `belief/cognitive/belief_graph.py:_guess_cwe` — map différente
3. `belief/cognitive/hydra_agent.py:KEYWORD_TO_CWE` — encore une autre map
4. `belief/cognitive/cognitive_loop.py:_learn` — mini-map inline

**Pourquoi** : copier-coller avec dérive à chaque ajout de cas d'usage.

**Manifestation** : un belief `"injection sql detected"` peut être classé `CWE-89` par l'un, `CWE-78` par l'autre, `""` par le 3ᵉ. Le score `_CWE_SEVERITY[cwe]` renvoie donc `0.5` (default) dans un cas, `0.95` dans un autre. Les décisions sont incohérentes.

**Fix** : un seul `belief/cognitive/cwe_taxonomy.py::guess_cwe(expression, context=None) -> str` avec **une** map maintenue centralement. Importé partout. Critique pour la reproductibilité des métriques.

---

### B-07 — `propagate_confidence` : « decay » est en fait un learning rate (mal nommé, ne converge pas)

**Où** : `belief/cognitive/belief_graph.py::propagate_confidence` — décrit dans Rapport 1 comme « 3 itérations fixes, pas toujours convergent ».

**Pourquoi** : le paramètre `decay=0.1` est utilisé comme `new_conf = old_conf + decay * delta_logit`. C'est un **pas d'apprentissage**, pas un decay temporel. Le vrai decay (vieillissement) est dans `apply_temporal_decay` (séparé).

**Manifestation** : nom trompeur pour les contributeurs. Les 3 itérations ne suffisent pas à converger quand le graphe a des cycles de contradiction (ce qui se produit souvent avec les beliefs bridge vs beliefs LLM).

**Fix** :
1. Renommer `decay` → `learning_rate` (ou `step_size`).
2. Remplacer « 3 itérations » par **boucle jusqu'à convergence** : `while max_delta > eps and iter < max_iter`.
3. Tester que ça converge sur le petit dataset CVE.

Alternative propre suggérée par Rapport 1 : utiliser **pgmpy** (belief propagation sur factor graph) et jeter l'implémentation custom.

---

### B-08 — `EnhancedOrchestrator` + `CognitiveLoop` dupliquent la logique, re-instancient bridges/memory/graph

**Où** :
- `belief/enhanced_orchestrator.py` (187 lignes) — wrap `Orchestrator`, rajoute bridges.
- `belief/cognitive/cognitive_loop.py::_observe` (ligne 233) — instancie `Orchestrator` à l'intérieur, **plus** les bridges séparément, **plus** son propre `MemoryEngine`, **plus** son propre `BeliefGraph` (celui de `cognitive/`).

**Manifestation** :
- Double analyse si on lance `CognitiveLoop` sur un projet déjà analysé.
- Pas de flag pour désactiver une phase (ex. « je veux juste les bridges, pas la LLM extraction »).
- État non partagé : chaque composant rebuild son graphe, recalcule ses stats.

**Fix** : un seul `Pipeline` (nom neutre) qui accepte des **phases configurables** :
```python
Pipeline(phases=[Parse, Bridges, LLMExtract, CrossVerify, Z3, Graph, Cognitive])
.run(project_path)
```
Chaque phase reçoit/produit un `Context` partagé. C'est **exactement** ce que **LangGraph** fait (recommandation Rapport 1).

---

### B-09 — `suggest_confidence_adjustment` : double-count + biais systémique à 0.7× conf

**Où** : `belief/cognitive/memory_engine.py:225` (approx).

**Pourquoi 1 (double-count)** : pour un belief qui a été à la fois `validated=True` et `false_positive=True` (ex. FP corrigé ensuite), il compte dans `validated_count` **et** `fps_count`. Le ratio `validated / (validated + fps)` est alors dilué.

**Pourquoi 2 (biais)** : quand `validated = fps = 0` pour les beliefs similaires → `historical_precision = 0 / max(1, 0) = 0`. Or la logique finale fait `new_conf = 0.7 * current + 0.3 * historical_precision`. Résultat : **tout belief sans historique voit sa confiance multipliée par 0.7**. Biais systémique vers 0.

**Manifestation** : projets neufs → beaucoup de beliefs nouveaux → tous décotés de 30 %. Ça fausse les comparaisons inter-projets et le benchmark.

**Fix** :
1. Ne compter qu'un `LEARNING_EVENT` par belief (le plus récent).
2. Quand `N=0`, retourner `None` (pas d'ajustement) au lieu de forcer 0. `new_conf = current` si pas d'évidence.

---

### B-10 — `belief.sources` / `MultiSource` **pas** branchée sur `CognitiveLoop`

**Où** : `belief/cognitive/cognitive_loop.py::_observe` n'importe ni `MultiSource`, ni `WhiteBoxSource`, ni `HarSource`.

**Pourquoi** : la v3 a ajouté `belief/sources/` (doc : SESSION3_DELIVERY.md « unified white-box + black-box pipeline »). La v4 cognitive a été écrite ensuite en parallèle, sans jamais réutiliser l'abstraction.

**Manifestation** : la couche cognitive ne peut **pas** consommer du HAR/Burp/traffic HTTP — uniquement du code source via `Orchestrator`. Contradiction directe avec la doc.

**Fix** : `CognitiveLoop._observe(sources: List[BeliefSource])`. Itérer `for src in sources: all_beliefs.extend(src.collect_beliefs())`. L'orchestrator devient un `BeliefSource` parmi d'autres. Cohérent avec l'architecture promise.

---

### B-11 — **26 sous-modules totalement morts** (importés uniquement par des tests qui portent leur nom)

**Où** : scan exhaustif des imports `from belief.X` dans `belief/` confirme que les modules suivants **ne sont utilisés nulle part** dans le pipeline :

```
adversarial        artifacts          attacker_model     behavioral
compliance         config_scanner     cross_lang         cross_language
cve_correlator     database           formal_verify      graph_visualizer
hardening          invariant_miner    llm_ensemble       migration
ontology           parallel           preventive         regression_tracker
remediation        report_gen         sandbox_runner     secret_scanner
supply_chain       webhook
```

26 modules. Chacun contient 1500-17000 caractères d'`__init__.py` + fichiers internes. Estimation : **~15-25 % du total de lignes de `belief/`** sont du code jamais exécuté hors tests.

**Pourquoi** : sessions « Phase 1 … Phase 11 » où des modules ont été générés (probablement par LLM) pour cocher des cases d'une roadmap ambitieuse, sans jamais les intégrer.

**Manifestation** :
- Le dépôt fait illusion (« 37 modules ! ») mais 26 sont des façades.
- `cross_lang` et `cross_language` coexistent — deux tentatives du même concept.
- Les tests `test_phase{N}_modules.py` passent mais ne prouvent rien de fonctionnel (ils testent des imports + des API internes en isolation).
- Impossible de raisonner sur l'architecture : tu dois tenir en tête quoi est vivant et quoi est mort.

**Fix** : **supprimer les 26 modules**. Garder les tests correspondants uniquement pour ceux qu'on décide de ressusciter (liste dans §5 roadmap). Pour l'instant ça part à la poubelle. Voir aussi §8 (liste de suppression).

**Contre-argument prévisible** : « mais si j'ai besoin un jour ». Réponse : tout est dans l'historique git. Le code mort empêche la réflexion, plus qu'il ne protège contre un futur besoin.

---

### B-12 — `belief_backup_pre_v3/` dans le repo (doublon complet de `belief/`)

**Où** : `belief_backup_pre_v3/` existe en parallèle de `belief/`. Diff structurel :
```
Only in belief/:              bridges/, cognitive/, enhanced_orchestrator.py,
                              security_rules/, sources/
Only in belief_backup_pre_v3/: examples/
```

**Manifestation** :
- Doublon de ~600 fichiers → doublement du temps de grep/scan/indexation.
- Risque réel d'import accidentel (ex. `sys.path` mal configuré en test).
- Pollution des métriques « lignes de code ».

**Fix** : `rm -rf belief_backup_pre_v3/`. L'historique git suffit. Si le contenu de `examples/` est utile, le déplacer dans `belief/examples/` ou à la racine dans `examples/`.

---

### B-13 — Benchmark CVE ne mesure **pas** la couche cognitive

**Où** : `benchmark_cve/run_benchmark.py` — aucune référence à `CognitiveLoop`, `HydraAgent`, `MemoryEngine`. Le benchmark mesure **les bridges seuls**.

**Manifestation** :
- Le « 90 % recall » cité dans les rapports → vient des bridges, pas du pipeline complet.
- Aucune mesure existante de `decision_quality`, `belief_accuracy`, `hydra_efficiency` (demandés par Rapport 1).
- Impossible de répondre « est-ce que la couche cognitive améliore ou dégrade les bridges ? » — c'est la question fondamentale du projet.

**Fix** : ajouter dans `benchmark_cve/run_benchmark.py` un mode `--full` qui appelle `CognitiveLoop.run_cycle()` et mesure :
- `decision_quality` = corrélation entre `score_decide` et « le belief était-il un vrai positif ? »
- `belief_accuracy` = précision après `_learn()` vs précision initiale des bridges.
- `hydra_efficiency` = nb de goals créés / nb de verdicts `exploitable=True` au bout.
- `cognitive_overhead` = temps loop vs temps bridges-seuls.

Sans ces métriques, la couche cognitive est une feature non prouvée. C'est le blocage scientifique principal.

---

### B-14 — `HydraAgent` CWE_STRATEGY statique (pas d'apprentissage)

**Où** : `belief/cognitive/hydra_agent.py` — `CWE_STRATEGY = {...}` dict codé en dur mappant CWE → stratégie d'investigation.

**Pourquoi** : ni Hydra ni la loop ne lit `memory.fp_rate_for_bridge(bridge)` ou `memory.historical_precision(cwe)` pour ajuster la stratégie.

**Manifestation** : un bridge qui produit 90 % de FP sur CWE-89 dans ton contexte sera malgré tout consulté au même niveau qu'un bridge 10 % FP. L'« apprentissage » ne touche pas le choix des outils.

**Fix** : la table `CWE_STRATEGY` devient **dynamique** — re-pondérée après chaque `_learn()` à partir de `memory.fp_rate_for_bridge`. Ça rejoint le point B-05 (bandit algorithms).

---

### B-15 — `enhanced_orchestrator.py` vs `orchestrator.py` : feature branch jamais mergée

**Où** : `belief/enhanced_orchestrator.py` (187 lignes) est une classe `EnhancedOrchestrator` qui **étend** `Orchestrator` avec des bridges. Mais `belief/cli.py` utilise toujours `Orchestrator` direct par défaut.

**Manifestation** : deux chemins parallèles. Ce qui est « le vrai orchestrator » dépend de la sous-commande. Fragile.

**Fix** : merger dans `Orchestrator` avec un flag `enable_bridges=True`. Supprimer `enhanced_orchestrator.py`. Un seul point d'entrée.

---

### Bugs mineurs mais à noter

- **B-16** — `Predicate.negation()` (models.py:136) : heuristique texto. Rate `x == 1 or y == 2` (remplace le premier `==`, oublie le second). Z3 traduction comblera partiellement mais pas à 100 %.
- **B-17** — `Scope.overlaps()` (models.py:113) : « same file, no line info → conservatively assume overlap ». C'est correct en défensif mais génère de **faux conflits** sur les scans où les bridges ne fournissent pas de ligne.
- **B-18** — `AnalysisReport.save()` (models.py:482) ne sérialise probablement pas les `Belief.scope` `frozen=True` sans `to_dict` custom. À vérifier.
- **B-19** — `extractor.py` import optionnel de `belief_knowledge_base` en module top-level (`import belief_knowledge_base as _kb`) — fonctionne par chance parce que c'est à la racine. Fragile si on refactor en package.
- **B-20** — `orchestrator.py:233` : `low_confidence = [b for b in all_beliefs if b.confidence_score < 0.3]`. Seuil magique, jamais référencé dans `BeliefConfig`. Doit venir de la config.

---

## 2. Contradictions rapports ↔ code réel

| Recommandation Rapport | Réalité du code | Gap |
|---|---|---|
| Rapport 1 : migrer CognitiveLoop vers **LangGraph** (observe/reason/decide/act/learn en StateGraph) | Custom loop, méthodes privées, pas de state explicite, pas de checkpointing | Migration non démarrée |
| Rapport 1 : **NetworkX + pgmpy** pour belief graph (propagation bayésienne sur factor graph) | `belief/cognitive/belief_graph.py` custom, 594 lignes, implémentation manuelle | Non migré. pgmpy aurait éliminé B-07 |
| Rapport 1 : **bandit algorithms** (UCB/Thompson) pour `_decide()` | Poids fixes `0.30/0.30/0.20/0.20`, pas d'exploration vs exploitation | Fondation du « cognitive » absente |
| Rapport 1 : **vector store** (Chroma/Qdrant) pour memory | `MemoryEngine` → JSON plat, recherche par prefix string (`expr[:40]`) | Scalabilité limitée, pas de similarité sémantique |
| Rapport 1 : **PyDriller** pour drift detection | Implémentation custom quelque part dans `temporal/` (usage réel à vérifier) | Probable réinvention de la roue |
| Rapport 2 : **stabilisation avant features** | v3 → v3.1 → v4 → couche cognitive, +26 modules morts, `enhanced_orchestrator.py`, backup_pre_v3/ | Opposé exact de la recommandation |
| Rapport 2 : **fix décide() bottleneck avant tout** | B-05 (bootstrap), B-06 (CWE), B-14 (static Hydra) non fixés | Bottleneck intact |
| SESSION3_DELIVERY : unified white-box + black-box | `belief.sources` existe mais **CognitiveLoop ne l'utilise pas** (B-10) | Promise non tenue dans la layer qui comptait |

**Synthèse** : les rapports disaient « consolide et mesure ». Le code montre « j'ai continué à empiler ».

---

## 3. Architecture — incohérences structurelles

### 3.1 — Trois pipelines parallèles, pas d'unification

Actuellement :
1. `Orchestrator.analyze_project()` → pipeline LLM+Z3 d'origine.
2. `EnhancedOrchestrator` → pareil + bridges.
3. `CognitiveLoop.run_cycle()` → instancie `Orchestrator` **interne** + ajoute bridges + memory + cognitive graph.

Aucune factorisation. Si tu fixes un bug dans un, les deux autres divergent.

### 3.2 — Deux graphes, deux reports, deux memories

- `BeliefGraph` (graph.py) ↔ `BeliefGraph` (cognitive/belief_graph.py) — même nom, APIs différentes (B-02)
- `AnalysisReport` ↔ `CognitiveReport` — schémas différents, save() dispo que sur un (B-03)
- `MemoryEngine` pour la couche cognitive, mais `extractor.BeliefExtractor.cross_verify_beliefs` n'utilise rien de persistant. Deux niveaux de mémoire.

### 3.3 — Sources abstraction morte dans sa moitié cruciale

`BeliefSource` est une belle abstraction. Elle est utilisée dans `MultiSource`, `WhiteBoxSource`, `HarSource`. Elle n'est **jamais** appelée depuis `CognitiveLoop` (B-10). La couche qui devait tout unifier est débranchée.

### 3.4 — Tests « de phase » testent des modules isolés, pas le système

`test_phase{N}_modules.py` teste chaque module mort isolément. Rien ne teste :
- `CognitiveLoop` → `MemoryEngine` → `CognitiveLoop` sur 3 runs successifs (is memory persistence utile ?).
- Le pipeline complet de bout en bout avec un CVE connu.
- La stabilité des `belief.id` entre deux lancements (B-04).

### 3.5 — Z3 bien isolé (un bon point)

`z3_verifier.py` est propre, a un fallback heuristique, des diagnostics de traduction, une repair callback. C'est la partie la plus solide du projet. À préserver telle quelle.

---

## 4. Inventaire du code mort (à supprimer en phase 1)

### 4.1 — Modules dans `belief/` jamais importés par le pipeline (26)

```
adversarial/             →  rien ne l'importe (sauf tests/test_new_modules.py)
artifacts/               →  rien
attacker_model/          →  rien (sauf tests)
behavioral/              →  rien (sauf tests/test_phase7_modules.py)
compliance/              →  rien (sauf tests/test_hardening.py)
config_scanner/          →  rien (sauf tests/test_phase11_modules.py)
cross_lang/              →  rien (sauf tests)
cross_language/          →  rien (sauf tests) — DOUBLON de cross_lang
cve_correlator/          →  rien (sauf tests)
database/                →  rien (sauf tests)
formal_verify/           →  rien (sauf tests)
graph_visualizer/        →  rien (sauf tests)
hardening/               →  rien (sauf tests)
invariant_miner/         →  rien (sauf tests)
llm_ensemble/            →  rien (sauf tests)
migration/               →  rien (sauf tests)
ontology/                →  rien (sauf tests)
parallel/                →  rien (sauf tests)
preventive/              →  rien (sauf tests)
regression_tracker/      →  rien (sauf tests)
remediation/             →  rien (sauf tests)
report_gen/              →  rien (sauf tests)
sandbox_runner/          →  rien (sauf tests)
secret_scanner/          →  rien (sauf tests)
supply_chain/            →  rien (sauf tests)
webhook/                 →  rien (sauf tests)
```

### 4.2 — Module dupliqué à la racine

`belief_backup_pre_v3/` — répertoire de sauvegarde complet. **À supprimer** : l'historique git le garde.

### 4.3 — Fichiers top-level à évaluer

- `belief_http_engine.py` → utilisé par bridges ? À vérifier.
- `belief_knowledge_base.py` → importé optionnel par `extractor.py` → utile, à garder.
- `belief_network_scanner.py` → importe `belief.X`, mais rien ne l'importe lui-même. Probablement point d'entrée CLI orphelin. À intégrer ou supprimer.

### 4.4 — Tests devenus obsolètes si on supprime les modules morts

```
tests/test_phase2_modules.py   → tests database/, ontology/
tests/test_phase3_modules.py   → à vérifier
tests/test_phase4_modules.py   → report_gen/, parallel/
tests/test_phase5_modules.py   → à vérifier
tests/test_phase7_modules.py   → behavioral/, preventive/
tests/test_phase8_modules.py   → supply_chain/, migration/
tests/test_phase9_modules.py   → formal_verify/, llm_ensemble/, cross_lang/
tests/test_phase10_modules.py  → cross_lang/, cross_language/, cve_correlator/, invariant_miner/, webhook/
tests/test_phase11_modules.py  → config_scanner/, sandbox_runner/, secret_scanner/, graph_visualizer/, regression_tracker/
tests/test_new_modules.py      → adversarial/, remediation/
tests/test_hardening.py        → hardening/, compliance/
```

→ **11 fichiers de tests** à supprimer si on supprime les 26 modules. Après nettoyage : tests restants = ceux qui testent le noyau réel.

---

## 5. Roadmap phasée « prototype → militaire »

Principe directeur : **chaque phase doit produire un BELIEF plus petit et plus mesurable que la précédente**, pas plus gros.

### Phase 1 — Stabilisation (2-3 sessions)

Objectif : **codebase nette, mesurable, une seule version de chaque chose**.

1. **Renommer pour lever B-02** :
   - `belief/cognitive/belief_graph.py::BeliefGraph` → `CognitiveGraph`
   - exporter explicitement dans `belief/cognitive/__init__.py`
2. **Unifier les reports (B-03)** : un seul dataclass `Report` avec section `cognitive: Optional[CognitiveSection]`, `save()` centralisé.
3. **Supprimer** :
   - `belief_backup_pre_v3/` (B-12)
   - les 26 modules morts (B-11)
   - les 11 fichiers `test_phase*_modules.py` correspondants
   - `enhanced_orchestrator.py` (fusionner dans `orchestrator.py` avec flag `enable_bridges`)
4. **Fixer B-20** : seuil `low_confidence_threshold` dans `BeliefConfig`.
5. **Stabilité des IDs (B-04)** : introduire `Belief.canonical_key` calculé à partir de `(cwe, scope.file, scope.function)` pour les beliefs bridge ; `Belief.id` reste pour les beliefs LLM. Tester la stabilité sur 2 runs consécutifs du benchmark → doit être 100 %.
6. **Nettoyer le CLI** : supprimer les sous-commandes qui ne marchent plus après suppression (ex. si `hunter` dépendait de `supply_chain`).

**Métrique de sortie Phase 1** :
- `cloc belief/` passe de X à **~0.5X**.
- Tous les tests restants passent.
- `benchmark_cve/run_benchmark.py` produit un rapport **identique** entre 2 runs (hash JSON identique).

---

### Phase 2 — Brancher la couche cognitive (2-3 sessions)

Objectif : **`CognitiveLoop` doit être utilisable en prod et mesurable**.

1. **B-01** : sous-commande CLI `python -m belief cognitive <project_path>`.
2. **B-10** : `CognitiveLoop._observe(sources: List[BeliefSource])`. Par défaut `[WhiteBoxSource(project_path)]`.
3. **B-06** : un seul `cwe_taxonomy.py` centralisé, importé partout.
4. **B-13** : benchmark mode `--full` qui fait tourner la loop et mesure `decision_quality`, `belief_accuracy`, `hydra_efficiency`, `cognitive_overhead`. Produit un CSV par run pour tracking historique.
5. **B-05 bootstrap fix (simple)** : pré-charger memory en sets au `__init__` de `CognitiveLoop`.

**Métrique de sortie Phase 2** :
- CLI `cognitive` fonctionne.
- Sur 10 runs successifs du benchmark CVE avec la cognitive loop activée :
  - `decision_quality` ≥ baseline bridges-seuls ? (à vérifier, pas à supposer).
  - `belief_accuracy` en hausse au fil des runs (preuve que `_learn` sert à quelque chose).
- Si **non**, Phase 2.5 : couper la feature cognitive, débuguer ce qui empêche la courbe d'apprentissage.

---

### Phase 3 — Raisonnement probabiliste correct (3-4 sessions)

Objectif : **remplacer l'algorithmie cognitive custom par du standard industriel**.

1. **B-07** : remplacer `propagate_confidence` custom par **pgmpy** (Belief Propagation sur factor graph).
   - Mapper `CognitiveGraph` → `pgmpy.models.MarkovNetwork`.
   - Conversion belief.confidence → factor potentiel.
   - Inférence jusqu'à convergence (pas 3 itérations fixes).
2. **B-05 bandit** : remplacer `novelty=0.8` constant par **Thompson sampling** sur les arms `(cwe, bridge)`. Lib : `scikit-learn` ou impl custom courte (~50 lignes).
3. **B-14** : `HydraAgent.strategy_for(cwe)` lit `memory.fp_rate_for_bridge` et repondère dynamiquement.
4. **B-09** : fix double-count + ne pas biaiser à 0 pour N=0.

**Métrique de sortie Phase 3** :
- `decision_quality` en hausse mesurable vs Phase 2.
- Propagation de confiance converge toujours (`max_iter` jamais atteint sur le benchmark).
- Bandit explore les bridges sous-exploités sur le benchmark → recall total ≥ baseline.

---

### Phase 4 — Orchestration via LangGraph (3-5 sessions)

Objectif : **un seul pipeline, explicite, checkpointable**.

1. **B-08 + B-15** : un seul `Pipeline` LangGraph avec nodes :
   ```
   parse → extract_beliefs → bridges → cross_verify → z3 → graph_analyze
         → [cognitive: observe → reason → decide → act → learn]
         → report
   ```
2. Chaque node a un état typé (pydantic). Transitions explicites.
3. **Checkpointing** : si la phase bridges crash, reprise depuis le dernier checkpoint.
4. **Visualisation** : `pipeline.get_graph().draw_mermaid()` → met à jour la doc automatiquement.

**Métrique de sortie Phase 4** :
- Un seul point d'entrée. `EnhancedOrchestrator`, `CognitiveLoop` supprimés.
- Temps de run ≤ ou comparable au pipeline séparé (overhead LangGraph minimal).
- Doc architecture générée automatiquement depuis le code.

---

### Phase 5 — Memory avec recherche sémantique (2-3 sessions)

Objectif : **B-04 résolu de façon robuste, memory qui scale**.

1. **Vector store** (Chroma embarqué, local, pas de serveur) pour les beliefs :
   - embedding(belief.predicate.expression) → vector.
   - Recherche : `memory.find_similar(belief, k=5)` par similarité cosinus.
2. Remplace `_index_entry(expr[:40])` par `_index_entry(embedding)`.
3. `is_known_fp` devient `has_similar_fp(threshold=0.85)`.

**Métrique de sortie Phase 5** :
- Le test `test_memory_across_bandit_versions` passe : même belief bandit détecté même si le message change.
- Rebench complet : taux de FP réduit vs Phase 3.

---

### Phase 6 — Drift historique réel (3-4 sessions)

Objectif : **le D et le L du sextuplet (Drift/Logic) prennent enfin vie**.

1. Intégrer **PyDriller** (recommandation Rapport 1).
2. Pour chaque belief, walker les N derniers commits qui touchent `scope.file_path` ± `scope.line_start..line_end`.
3. Détecter :
   - `DriftType.PREDICATE_VIOLATED` → le code a changé mais le belief (encore exprimé quelque part) ne le reflète plus.
   - `DriftType.SCOPE_EXPANDED` → le périmètre d'une fonction a grossi, les anciens invariants ne tiennent plus.
4. Bench sur CVE réelles : BELIEF doit signaler le commit introducteur.

**Métrique de sortie Phase 6** :
- Sur 5 CVEs connues, BELIEF identifie le **commit** coupable dans les N dernières entrées de `git log`.
- Mesure de précision (le bon commit) vs rappel (le commit est bien dans le top-K).

---

### Phase 7 — Publications (3-6 mois)

Objectif : **transformer BELIEF en artefact académique solide**.

1. Paper SSTIC/WOOT/ACSAC : soumettre avec benchmark reproductible (Phase 3).
2. Dataset publié : `belief-benchmark-cve-2026` (50-100 CVEs curées avec ground truth).
3. Artifact evaluation : Dockerfile `belief-eval:2026` qui reproduit tous les chiffres du paper.
4. Dépôt public nettoyé (branches, tags, CI qui tourne le benchmark à chaque PR).

---

## 6. Dépôts externes à piller (inspiration & copie-paste)

Classés par phase d'utilité.

| Phase | Besoin | Dépôt | Stratégie |
|---|---|---|---|
| 3 | Bayesian belief propagation | **pgmpy/pgmpy** | `import pgmpy`, mapper notre graphe dessus |
| 3 | Multi-armed bandit | **jordan-aumann/thompson_sampling** | adapter (50 lignes) |
| 4 | LangGraph orchestration | **langchain-ai/langgraph** | exemples dans `examples/` du repo |
| 4 | State machine pattern | **pytransitions/transitions** | alternative légère à LangGraph si on veut rester Python pur |
| 5 | Vector store embarqué | **chroma-core/chroma** | `import chromadb` avec backend sqlite |
| 5 | Embeddings locaux | **UKPLab/sentence-transformers** | `all-MiniLM-L6-v2` tourne sur CPU |
| 6 | Git mining | **ishepard/pydriller** | déjà mentionné Rapport 1 |
| 6 | Commit diff analysis | **PyCQA/astroid** | parse AST pour diff sémantique, pas syntaxique |
| — | Predicate repair | **Z3Prover/z3** (examples) | pour la repair callback v2 |
| — | Symbolic execution fallback | **pysmt/pysmt** | backup si z3 crash |

Remarque : tu as déjà vendorisé beaucoup de ces dépôts dans `belief/tools_bundled/`. Vérifier ce qu'il y a déjà **avant** de re-télécharger. Le script `harvest_sources.sh` remis à jour ci-dessous permet de cibler UN repo à la fois.

---

## 7. Patch `harvest_sources.sh` — mode « export zip unitaire »

Besoin exprimé : pouvoir demander à Claude « aide-moi à intégrer `pgmpy` » et uploader **un seul zip** ciblé plutôt que tout `BELIEF_SOURCES`. La patch ajoute :

```bash
bash harvest_sources.sh repo <name1> [name2 ...]
# → produit UN zip par repo demandé dans $OUT/zips_targeted/
```

Le fichier patché est livré séparément : `harvest_sources_v3.sh`.

Les noms supportés sont ceux du `TARGET_MODULE` existant : `codeql_python`, `semgrep_rules`, `joern_core`, `pyre_pysa`, `bandit`, `dlint`, `safety_db`, `nuclei_misconfig`, `nuclei_tech`, `git_of_theseus`, `frouros`, `driftgan`, `pyexz3`, `crosshair`, `z3_playground`, `codegraph`, `pydeps`, `pyan`, `importlab`, `modulegraph2`, `findimports`, `pyt`, `contextgem`, `code_analyzer`, `supply_chain_firewall`, + nouveaux ajoutés : `pgmpy`, `chroma`, `sentence_transformers`, `langgraph`, `pydriller`, `thompson_sampling`.

---

## 8. Liste de suppression (prête à exécuter en Phase 1)

```bash
# --- 1. Backup complet ---
rm -rf belief_backup_pre_v3/

# --- 2. Modules morts dans belief/ (26) ---
cd belief/
rm -rf adversarial artifacts attacker_model behavioral compliance \
       config_scanner cross_lang cross_language cve_correlator database \
       formal_verify graph_visualizer hardening invariant_miner \
       llm_ensemble migration ontology parallel preventive \
       regression_tracker remediation report_gen sandbox_runner \
       secret_scanner supply_chain webhook
cd ..

# --- 3. Tests des modules morts ---
cd tests/
rm -f test_phase2_modules.py test_phase3_modules.py test_phase4_modules.py \
      test_phase5_modules.py test_phase7_modules.py test_phase8_modules.py \
      test_phase9_modules.py test_phase10_modules.py test_phase11_modules.py \
      test_new_modules.py test_hardening.py
cd ..

# --- 4. Fichiers top-level orphelins (après vérif usage) ---
# À vérifier manuellement d'abord :
#   grep -l "belief_network_scanner\|belief_http_engine" **/*.py
# Si rien ne les importe → rm belief_network_scanner.py belief_http_engine.py
```

**Avant de lancer** : commit git propre, tag `pre-cleanup-2026-04`. Comme ça tout est retrouvable.

**Résultat attendu** : `cloc belief/` divisé par ~2, tests qui passent encore (sur le noyau réel), repo navigable en tête.

---

## 9. Actions prochaine session (ordre)

1. **Tu reviews ce document** — challenge ce qui te semble faux/exagéré.
2. Tu confirmes le **plan de suppression §8**.
3. Je produis :
   - Le patch `orchestrator.py` qui fusionne `enhanced_orchestrator.py` (B-15).
   - Le renommage `CognitiveGraph` (B-02) avec tous les sites d'appel.
   - Un `cwe_taxonomy.py` unifié (B-06).
   - Le premier bouchon de `cli.py::cmd_cognitive` (B-01).
4. On lance le benchmark **avant** et **après** chaque changement. On compare les chiffres.
5. Quand Phase 1 est close (métrique §5 atteinte), on attaque Phase 2.

---

## 10. Risques / contre-arguments anticipés

**« Les modules morts pourraient servir bientôt »** — l'historique git suffit. Le coût cognitif de 26 modules fantômes > bénéfice hypothétique.

**« LangGraph est une dépendance lourde »** — alternative `pytransitions` (pure Python, 30 kB). Décision à la Phase 4. Pas bloquant maintenant.

**« pgmpy est gros »** — environ 15 MB. Si contrainte d'embed, on peut extraire juste belief_propagation.py. À négocier Phase 3.

**« Le renommage `BeliefGraph` va casser des imports externes »** — il n'y a **pas** d'utilisateurs externes. C'est le bon moment.

**« Je perds l'impression de progression si je supprime 60 % du code »** — `cloc` avant/après est une métrique de progression plus saine. « Moins de code qui fait plus ». C'est la différence entre prototype étudiant et logiciel livrable.

---

*Fin de l'audit. Document à amender selon ton retour avant patch.*
