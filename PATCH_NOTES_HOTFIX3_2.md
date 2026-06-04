# BELIEF v4 hotfix #3.2 — résout les 2 derniers points noirs du benchmark

Applique ON TOP de hotfix #3 + hotfix #3.1. Deux bugs diagnostiqués à
partir de ton dernier run (13/13 recall bridges, 0.92/0.92/0.85 cognitive).

## Les 2 bugs

### Bug 1 — CWE-918 SSRF : toujours 0 goal créé

**Symptôme** : `cwe_918_ssrf` → `total_goals=0` malgré un bandit B310 bien
détecté par les bridges.

**Cause** : `bandit_bridge.to_belief()` construisait l'assumption comme
`"Bandit B310 (blacklist) should not match here"` — **aucun mot-clé SSRF
dedans**. Le message réel de bandit (`"Audit url open for permitted
schemes..."`) vit dans `finding["issue_text"]` mais n'était jamais repris.
Donc :
- `Belief.cwe` = `""` (bandit_bridge ne propageait pas de cwe)
- `Belief.predicate.natural_language` = `"Bandit B310 (blacklist)..."`
- `guess_cwe_from_belief(b)` cherche SSRF → rien → `cwe=""`
- Garde-fou `b_cwe != ""` rejette → 0 goal

**Fix** : `bandit_bridge.to_belief()` incorpore `issue_text` dans
l'assumption ET set un champ `cwe` déterministe depuis une table
`_BANDIT_CODE_TO_CWE` (50+ codes mappés). Le `belief_adapter` (Pack B de
hotfix #2) propage déjà ce `cwe` vers `Belief.cwe`, donc le cognitive_loop
le voit directement sans passer par la taxonomie de texte.

### Bug 2 — cwe_89_sqli_multifile : REFUTED malgré sink bien trouvé

**Symptôme** : `1.00/1.00/0.00` — goal bien ciblé, belief précise,
mais Hydra retourne `REFUTED` (refuted_fps=1).

**Cause** : dans `_filter_relevant`, la comparaison des chemins échoue
sur les samples multi-fichiers. Quand Hydra appelle `_resolve_project_path`
sur `goal.target_file = /tmp/bench_cog_XXX/services/user_service.py`,
ça se réduit à `/tmp/bench_cog_XXX/services/`. Puis bandit/semgrep tournent
sur ce sous-dossier et retournent des findings avec des chemins normalisés
différemment (parfois juste basename, parfois relatif à la dir narrow).

Du coup :
- `goal.target_file` = `/tmp/bench_cog_XXX/services/user_service.py`
- `f.filename` = `user_service.py` (ou autre normalisation)
- `goal.target_file in f.filename` → False
- `f.filename in goal.target_file` → False aussi selon normalisation
- Finding jeté → `supports_hypothesis=False, confidence=0.3`

Avec 3 bridges retournant "not relevant" → `len(refuting) >= 2` et
`final_conf = 0` → verdict REFUTED. Alors que bandit avait trouvé pile le
bon bug !

**Fix** : `_filter_relevant` ajoute un fallback basename. Si ni substring
ni inverse-substring ne matchent, on compare les noms de fichier seuls.
C'est suffisant parce que `_resolve_project_path` a déjà narrowé la
recherche à la bonne dir — les collisions de basename entre différents
dirs du même projet deviennent très improbables après narrowing.

## Impact attendu

| Sample | Avant 3.2 | Après 3.2 |
|---|---|---|
| cwe_918_ssrf | 0.00 / 1.00 / 0.00 | **1.00 / 1.00 / 1.00** |
| cwe_89_sqli_multifile | 1.00 / 1.00 / 0.00 | **1.00 / 1.00 / 1.00** |
| cognitive AVG | 0.92 / 0.92 / 0.85 | **~1.00 / 0.95 / ~0.95** |

Et sur cwe_78_rce_multifile qui est à 1.00/0.67/1.00, bel_acc=0.67
signifie 1 belief sur 3 tombe hors ligne vuln. Probablement le FP bandit
B404 (subprocess import ligne 6). Pas grave pour l'instant — c'est un
finding bruitif qu'on peut filtrer au niveau du benchmark (liste noire
des codes bandit informationnels) dans un futur patch.

## Fichiers modifiés (2)

| Fichier | Changement |
|---|---|
| `belief/bridges/bandit_bridge.py` | `to_belief()` : issue_text dans assumption + table `_BANDIT_CODE_TO_CWE` (50+ codes) + champ `cwe` dans le dict retourné |
| `belief/cognitive/hydra_agent.py` | `_filter_relevant()` : fallback basename en plus du substring match |

## Application

```bash
cd /mnt/c/Users/tatam/Desktop/BELIEF_V2/belief_v4
unzip -o /path/to/belief_v4_hotfix3.2.zip

source .venv/bin/activate
python3 benchmark_cve/run_benchmark.py --full
```

## Sanity checks

```bash
# 1. B310 → CWE-918
python3 -c "
from belief.bridges.bandit_bridge import to_belief
b = to_belief({'test_id':'B310','issue_text':'Audit url open','issue_severity':'MEDIUM','issue_confidence':'HIGH','filename':'x.py','line_number':1})
print('cwe:', b['cwe'], '—', b['assumption'][:50])
"
# Attendu: cwe: CWE-918 — Bandit B310: Audit url open

# 2. Basename fallback
python3 -c "
import sys; sys.path.insert(0, '.')
from belief.cognitive.hydra_agent import HydraAgent
from belief.bridges import registry
from belief.cognitive.goal import Goal
from belief.cognitive.types import Goal as _ # shim
# Just check the method exists
agent = HydraAgent(bridge_registry=registry)
print('has _filter_relevant:', hasattr(agent, '_filter_relevant'))
"
```

## Ce qui reste (non corrigé par 3.2)

- **bel_acc=0.67 sur 3 samples** (cve_numpy_pickle, cwe_78_shell_injection,
  cwe_78_rce_multifile) : dans chacun, 1 belief sur 3 est un FP ligne 2
  (import bandit B403/B404 — noise on imports). Fix propre = filtrer ces
  codes dans `bandit_bridge.py` avant de les convertir en findings, ou les
  tagger comme `confidence=LOW` dans le belief. Policy call — j'attends
  ton go.

- **pyt crashes** sur tous les samples (`TypeError: expected str, bytes
  or os.PathLike object, not `). C'est dans `pyt_bridge.py`. Pour plus
  tard.

## Next step après 3.2

Si tes metrics passent bien à `~1.00 / 0.95 / ~0.95`, tu as atteint le
plateau de performance qu'on peut tirer des bridges actuels sur des
micro-samples. Les 2 prochaines directions réelles :

1. **Plus de samples multi-fichiers, plus variés** (4-5 fichiers, chaînes
   de propagation plus longues) → pour voir si la loop tient à plus grande
   échelle

2. **Un vrai projet opensource** — je reste sur ma reco
   flask-jwt-extended ou une lib AWS wrapper. Le but c'est de voir si
   BELIEF produit un finding QUE les outils classiques ratent. C'est THE
   validation pour SSTIC/WOOT/ACSAC. Pas besoin d'attendre un bench à
   100% pour commencer à expérimenter là-dessus en parallèle.
