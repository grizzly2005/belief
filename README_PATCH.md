# BELIEF v2 — PATCH CORRECTIF

## ⚠️ Si tu as déjà appliqué le patch v2 précédent (belief_v2_patch.zip)

Le patch précédent avait un bug : il écrasait deux `__init__.py` qui contenaient
du vrai code existant (653 + 586 lignes), les remplaçant par des stubs de 41+35
lignes qui importaient mes nouveaux fichiers.

**Résultat** : les classes `BeliefDependencyGraph`, `TransitiveConflict`,
`CascadeImpact`, `StronglyConnectedComponent`, `AdvancedDriftAnalyzer`,
`FunctionSignature`, `BlameEntry`, `CommitHotspot` et la première version de
`DriftEvent` ont disparu de `belief.dep_graph` et `belief.advanced_drift`.

**Ce patch CORRECTIF répare ça** : les `__init__.py` originaux sont restaurés
intégralement, et mes extensions v2 s'ajoutent proprement comme sous-fichiers.

---

## Comment appliquer

```bash
cd /chemin/vers/ton/BELIEF
# Backup (si pas déjà fait)
cp -r belief belief_backup_avant_patch_correctif

# Extraire
unzip -o belief_v2_correctif.zip
```

Ça écrase 15 fichiers :

### Core (6 fichiers — identiques au patch v1, ils ne cassaient rien)
- `belief/config.py`
- `belief/llm_client.py`
- `belief/prompts.py`
- `belief/extractor.py`
- `belief/z3_verifier.py`
- `belief/orchestrator.py`

### dep_graph (5 fichiers — dont __init__.py CORRIGÉ)
- `belief/dep_graph/__init__.py` ← **704 lignes** = tes 653 originales + section v2 en bas
- `belief/dep_graph/graph_core.py` (nouveau, 184 lignes)
- `belief/dep_graph/import_resolver.py` (nouveau, 290 lignes)
- `belief/dep_graph/call_graph.py` (nouveau, 328 lignes)
- `belief/dep_graph/cycle_detector.py` (nouveau, 193 lignes)

### advanced_drift (4 fichiers — dont __init__.py CORRIGÉ)
- `belief/advanced_drift/__init__.py` ← **629 lignes** = tes 586 originales + section v2
- `belief/advanced_drift/concept_drift.py` (nouveau, classe renommée en `ConceptDriftEvent` pour éviter collision avec ton `DriftEvent` original)
- `belief/advanced_drift/git_hotspots.py` (nouveau, 194 lignes)
- `belief/advanced_drift/belief_drift.py` (nouveau, 271 lignes)

---

## Ce qui est préservé

```python
# Ces imports marchent comme avant :
from belief.dep_graph import BeliefDependencyGraph, BeliefNode, BeliefEdge
from belief.dep_graph import EdgeType, TransitiveConflict, CascadeImpact
from belief.dep_graph import StronglyConnectedComponent

from belief.advanced_drift import AdvancedDriftAnalyzer
from belief.advanced_drift import FunctionSignature, BlameEntry
from belief.advanced_drift import CommitHotspot, DependencyChange, DriftEvent
```

## Ce qui est ajouté (nouveau, accessible via sous-modules)

```python
# Graphe de code syntaxique (complémentaire à BeliefDependencyGraph)
from belief.dep_graph.graph_core import DependencyGraph
from belief.dep_graph.import_resolver import ImportResolver, ImportKind
from belief.dep_graph.call_graph import CallGraphBuilder
from belief.dep_graph.cycle_detector import find_cycles, compute_hotspots

# Drift streaming (complémentaire à AdvancedDriftAnalyzer)
from belief.advanced_drift.concept_drift import PageHinkleyDetector, ADWINDetector
from belief.advanced_drift.concept_drift import ConceptDriftEvent  # renommé pour éviter collision
from belief.advanced_drift.git_hotspots import GitHotspotAnalyzer, FileHotspot
from belief.advanced_drift.belief_drift import BeliefDriftDetector, BeliefDelta
```

---

## Séparation conceptuelle

**BeliefDependencyGraph** (ton original, conservé) = graphe SÉMANTIQUE
entre beliefs. Nodes = Belief, edges = DEPENDS_ON / CONTRADICTS / etc.

**DependencyGraph** (nouveau) = graphe SYNTAXIQUE du code analysé.
Nodes = modules/fonctions, edges = imports/appels.

Les deux sont utiles et complémentaires : l'un raisonne sur les
croyances, l'autre sur la topologie du code lui-même.

Même logique pour le drift :
- **AdvancedDriftAnalyzer** (original) : analyse git history offline (blame,
  signatures de fonctions sur plusieurs commits).
- **PageHinkleyDetector / ADWINDetector** (nouveau) : détection online de
  drift sur un stream de métriques (pour CI qui tourne BELIEF régulièrement).

---

## Vérification après application

```bash
python3 -c "
from belief.dep_graph import BeliefDependencyGraph
from belief.dep_graph.graph_core import DependencyGraph
from belief.advanced_drift import AdvancedDriftAnalyzer
from belief.advanced_drift.concept_drift import PageHinkleyDetector
print('✓ Tout importe correctement')
"
```

Si tous les imports passent, le patch est correctement appliqué.
