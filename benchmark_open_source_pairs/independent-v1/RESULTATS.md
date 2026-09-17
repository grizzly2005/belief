# Évaluation indépendante — première mesure du 17 septembre 2026

**Les critères d'acceptation échouent.** La mesure de 24 paires est terminée,
sans erreur d'analyse et avec des répétitions identiques. Elle ne justifie
ni une fusion de release ni une annonce de détection fiable des mécanismes
concernés. Les scores ci-dessous sont les sorties inchangées du moteur v1.
Leur correspondance fichier/ligne/type surestime plusieurs attributions au
mécanisme de sécurité, comme détaillé plus bas.

## Révisions, sélection et portée

- Gel des entrées avant mesure : `a7c2488c670e460da4849c4d33ca5955c8b30615`.
- Détecteur et moteur de paires identiques à
  `83c65692239a85435cb8f17c0eb9a8cc951a1d9b` pendant cette mesure.
- 24 projets distincts, 48 versions et deux analyses par version :
  **96 analyses**. Une seule invocation du moteur de paires, en 120,983221 s,
  code de sortie **1** parce que trois seuils échouent.
- 300 avis uniques examinés ; les 24 projets sélectionnés sont disjoints
  des 253 identités antérieures exclues. Les populations et exclusions
  vérifiables figurent dans [selection.json](selection.json) et
  [project-exclusions.json](project-exclusions.json).
- 37 fichiers liés par empreinte, soit 74 blobs vulnérables/corrigés ;
  **27 fichiers analysés**, dix autres réservés à la qualification par lecture.
  Origines, relations parent/correctif, licences, hashes et syntaxe Python 3.12
  vérifiés avant mesure : [input-verification.json](input-verification.json).
- Les hypothèses de chaque contrôle corrigé restent celles de
  [qualification.json](qualification.json) : configuration, racine de
  confiance, plateforme, stabilité des chemins ou absence de liens hostiles
  selon le cas. Aucune certification globale de sûreté n'en découle.

Le protocole [PROTOCOL.md](PROTOCOL.md) et le manifeste [cases.json](cases.json)
ont été commités avant toute sortie du détecteur sur ces candidats. Aucun
seuil, contrôle, intervalle de score ou détecteur n'a été retouché pour
améliorer cette mesure. La localisation est informée par les correctifs et
les instantanés sont des sous-ensembles de sources, pas des dépôts complets.

## Résultats bruts et seuils

| Critère du moteur v1 | Mesure | Seuil gelé | Résultat |
|---|---:|---:|---|
| Variante vulnérable avec alerte dans la plage/type attendus | 6/24 = 25 % | ≥ 50 % | Échec |
| Variante corrigée avec alerte dans la plage/type attendus | 5/24 = 20,8333 % | ≤ 20 % | Échec |
| Paire avec alerte vulnérable et sans alerte corrigée localisée | 1/24 = 4,1667 % | ≥ 40 % | Échec |
| Variantes aux deux répétitions identiques | 48/48 = 100 % | 100 % | Réussi |
| Erreurs d'analyse | 0 | 0 | Réussi |

Le nom brut `vulnerable_warning_recall` ne signifie pas que six mécanismes
de CVE ont été reconnus. De même, `fixed_warning_false_positive_count` est
le nombre de variantes corrigées encore signalées selon le score localisé,
pas une estimation de précision générale. L'unique discrimination brute,
pip, ne prouve pas que le détecteur a compris sa garde.

| Projet | Alerte vulnérable localisée | Alerte corrigée localisée | Discrimination brute |
|---|---|---|---|
| mar10/wsgidav | Oui | Oui | Non |
| ronf/asyncssh | Non | Non | Non |
| mervinpraison/praisonai | Non | Non | Non |
| nltk/nltk | Non | Non | Non |
| mobsf/mobile-security-framework-mobsf | Non | Non | Non |
| huggingface/transformers | Oui | Oui | Non |
| keras-team/keras | Non | Non | Non |
| elyin/gemini-bridge | Non | Non | Non |
| thumbor/thumbor | Non | Non | Non |
| flytohub/flyto-core | Non | Non | Non |
| pypa/pip | Oui | Non | Oui |
| brightio/penelope | Oui | Oui | Non |
| datamodel-code-generator/datamodel-code-generator | Non | Non | Non |
| open-webui/open-webui | Non | Non | Non |
| facelessuser/pymdown-extensions | Oui | Oui | Non |
| berriai/litellm | Non | Non | Non |
| lepture/mistune | Oui | Oui | Non |
| dgtlmoon/changedetection.io | Non | Non | Non |
| microsoft/prompty | Non | Non | Non |
| snowflakedb/snowflake-sqlalchemy | Non | Non | Non |
| sooperset/mcp-atlassian | Non | Non | Non |
| jelmer/dulwich | Non | Non | Non |
| hanxi/xiaomusic | Non | Non | Non |
| oscal-compass/compliance-trestle | Non | Non | Non |

« Non » signifie absence d'alerte correspondante dans cet instantané et
cette plage ; cela ne signifie pas absence d'alertes ailleurs, ni sûreté du
code. Le dépôt nommé `gemini-bridge` n'a servi que de texte source statique.
Aucun bridge, serveur, CLI de ce projet ou code tiers n'a été exécuté.

## Vérification sémantique après mesure

Ces observations expliquent les limites du score sans modifier son résultat :

1. **Transformers : mauvaise opération attribuée.** Les ouvertures signalées
   aux lignes 3299 et 3310 concernent le template unique/par défaut, avec
   `save_directory` comme source. Le mécanisme qualifié concerne les clés de
   templates nommés dans l'autre branche, lignes 3316–3320. La racine de
   sauvegarde est de confiance dans le contrat du contrôle. Les alertes
   localisées ne démontrent donc pas la reconnaissance du mécanisme nommé.
2. **Penelope : provenance à élucider.** Le résultat normalisé associe la
   ligne 5132 au sink `Open(folder)` et à la source `self`. Dans le blob
   concerné, cette ligne appartient à une traduction de chemin HTTP ;
   l'appel `Open(folder)` apparaît vers 1250/1251 selon la variante. La plage
   commune 3261–5252 est large à cause du déplacement du code d'extraction.
   Une attribution à l'extraction tar n'est pas établie par ces alertes.
   Le défaut exact de provenance doit encore être retracé dans le moteur.
3. **pip : déplacement d'alerte hors de l'intervalle.** La variante vulnérable
   signale l'ouverture ligne 196 avec `location` comme source. La version
   corrigée garde une alerte dans `link.py`, ligne 74, au retour du helper,
   avec `component` comme source, hors de l'intervalle gelé 424–497 pour ce
   fichier. Le score « vulnérable seulement » ne valide pas la compréhension
   de la garde réelle.
4. **WsgiDAV : attribution SQL peu précise.** Les cas sont ancrés aux
   définitions de fonctions, lignes 383 et 412, sans source ni sink précis.
   Leur verdict de reportabilité est `likely_false_positive`, score 0, mais
   leur statut `needs_review` les fait compter dans le contrat du moteur.
   La qualification statique du correctif paramétré reste documentée.
5. **PyMdown et Mistune : alertes persistantes sur les flux qualifiés.** Les
   ouvertures corrigées, respectivement lignes 94 et 70, restent signalées
   malgré les gardes lues avant mesure. Leur interprétation doit conserver
   les hypothèses de chemins et de liens ainsi que le contexte incomplet
   présenté au détecteur.

Il n'y a pas eu de nouvelle notation manuelle destinée à remplacer les
scores échoués. Les sources et mécanismes des 18 paires non signalées ne
sont pas déclarés correctement compris par le détecteur.

Le champ historique `unrelated_warning_count` compte seulement les autres
catégories. Il ne compte pas toutes les alertes hors de la plage cible.
La partition complète, par première répétition de chaque variante, est :

| Alertes | Vulnérables | Corrigées |
|---|---:|---:|
| Toutes catégories et positions | 51 | 50 |
| Même catégorie, dans la plage | 7 | 7 |
| Même catégorie, hors de la plage | 20 | 18 |
| Autres catégories, champ historique `unrelated_warning_count` | 24 | 25 |
| Total hors correspondance localisée | 44 | 43 |

Le compte d'alertes peut dépasser le compte de variantes signalées.

## Six témoins bénins et diagnostic général

Le contrôle séparé rend **5/6 fonctions sans alerte**, 6/6 répétitions
identiques, aucune erreur d'analyse, code **1**, durée interne 0,160252 s.
WsgiDAV, NLTK, Thumbor, pip et Snowflake passent. La fonction pure Praison
`_sanitise_user_id` reçoit une alerte `idor_bola_possible`, `needs_review`,
score 30 (`weak_signal`), sans requête, accès à une ressource ni entrée/sortie.
Cela ne modifie pas le dénominateur des 24 projets.

Après mesure, un diagnostic synthétique a croisé deux noms de fonction avec
deux noms d'argument, en ne faisant que `return argument.strip()` :

| Fonction | Argument | Alertes IDOR, chacune des deux répétitions |
|---|---|---:|
| `normalize_label` | `value` | 0 |
| `normalize_label` | `user_id` | 1 |
| `normalize_user_id` | `value` | 0 |
| `normalize_user_id` | `user_id` | 1 |

La reproduction isole l'effet du nom d'argument. À la révision gelée,
`belief/hypothesis_engine.py:185–202` classe une hypothèse d'autorisation
sur simple présence de `user_id`, `owner_id` ou `source_id` dans le texte
d'un constat ; les garanties demandées aux lignes 526–531 supposent ensuite
un contexte de route et de ressource. Le diagnostic est une preuve de
développement postérieure à la mesure, pas un nouvel échantillon indépendant.
Il ne justifie aucune exception portant le nom d'un projet ou d'un CVE.

## Validation, ressources et reproduction

Avant le gel, les tests ciblés du contrat et de l'intégration passent :
**19 réussis en 2,59 s**, code 0. Ruff sur le nouveau pilote bénin passe,
code 0. Commandes exécutées depuis la racine BELIEF :

```powershell
.venv\Scripts\python.exe -m pytest tests/test_open_source_pairs_benchmark.py tests/test_open_source_detector_integration.py -q -p no:cacheprovider
.venv\Scripts\python.exe -m ruff check benchmark_open_source_pairs/independent-v1/evaluate_benign_controls.py
.venv\Scripts\python.exe scripts/run_open_source_pairs_benchmark.py --manifest benchmark_open_source_pairs/independent-v1/cases.json --repos-root F:\belief-rd\open-source-independent-v1\repos --output F:\belief-rd\open-source-independent-v1\pair-result-a7c2488.json
.venv\Scripts\python.exe benchmark_open_source_pairs/independent-v1/evaluate_benign_controls.py --repos-root F:\belief-rd\open-source-independent-v1\repos --output F:\belief-rd\open-source-independent-v1\benign-result-a7c2488.json
```

Les deux mesures ont exigé un checkout propre au commit de gel. Les
résultats ont été copiés dans le dépôt après leurs exécutions. Pour les
reproduire, utiliser cette révision et des chemins de sortie neufs ; les
pilotes refusent l'écrasement. Les objets Git doivent déjà être présents :
réseau et chargement implicite de blobs sont désactivés pendant la mesure.

L'instantané du 17 septembre à 17:56:44, heure de Paris, indiquait 32,8 Gio
de RAM libres, 5 % de charge CPU et Overwatch en cours. Les traitements
étaient séquentiels, priorité `BelowNormal`, affinité `3` soit deux
processeurs logiques sur 32. Les processus Python observés totalisaient
environ 70–95 Mio. Aucun calcul GPU, changement du jeu ou arrêt d'application.
Cet instantané ne constitue pas une mesure continue des performances du jeu.

La régression générale historique de 1868 tests et le benchmark historique
de trois projets n'ont pas été relancés pour ce lot d'artefacts. Leurs
résultats antérieurs, dont le benchmark échoué, restent conservés.
Les tests des projets tiers n'ont pas été exécutés.

## Artefacts et empreintes

Le résumé exploitable est [measurement-summary.json](measurement-summary.json).
Les trois sorties complètes sont conservées sans modification des octets :

| Artefact | Octets | SHA-256 |
|---|---:|---|
| [pair-result-a7c2488.json](pair-result-a7c2488.json) | 4492911 | `6175da704e357176625e4a0971cce31bfdc056af1310d2af6e0a50af2e94875e` |
| [benign-result-a7c2488.json](benign-result-a7c2488.json) | 10529 | `cbe1128acccbddec7a6b425f48b9278b12a96d5ddecd8de4002727eeb1325505` |
| [label-probe-a7c2488.json](label-probe-a7c2488.json) | 8698 | `2adc0710e688142e2f1414fde6ac4eba962cb7e056f72b3f0086672fed8c9846` |

Le probe brut est marqué `-text` dans `.gitattributes` pour préserver ses
fins de ligne CRLF et son empreinte après un checkout. Les deux résultats
des pilotes sont déjà en LF. Le résumé est un artefact dérivé.

- Manifeste des paires : `350db7418224aac1fcb3619e52a423c4a9ebfb84e57a39b61d77d97fb5bec9a5`.
- Digest déterministe des paires : `373d22377d3736931fa5edd354db6ab5d3de1dfe23441099081122f30d3be83d`.
- Digest déterministe bénin : `b1939b52ff37c6523b1dba39e36da332206287f9231288a0d900501f94baff85`.

## Suite logique

1. Corriger la classification d'autorisation avec des contre-exemples
   synthétiques et de vrais cas positifs, en exigeant une indication de
   sécurité pertinente plutôt qu'un nom d'argument.
2. Retracer les relations constat → hypothèse → source/sink → ligne,
   notamment pour Penelope, puis préparer un contrat de score séparé qui
   n'assimile plus toute alerte de la bonne catégorie à un mécanisme reconnu.
3. Étudier la propagation des gardes et les opérations manquantes avec des
   tests génériques, en conservant ce premier résultat échoué.
4. Après ajustement, utiliser une nouvelle population de projets pour toute
   nouvelle affirmation de généralisation. Ce corpus est désormais connu
   et sert de preuve de développement.
