#!/bin/bash
# ============================================================================
#  BELIEF — Harvest des sources open-source pour améliorer le raisonnement
#
#  v3 — Nouveautés par rapport à v2 :
#    - Mode "repo <name1> [name2] ..." : ne clone/zippe que les repos
#      demandés, pour uploader UN seul zip ciblé sur Claude.
#      Ex: bash harvest_sources_v3.sh repo pgmpy chroma
#          → produit ./zips_targeted/pgmpy.zip + ./zips_targeted/chroma.zip
#    - Ajout des sources de la roadmap Phase 3→6 :
#        pgmpy (bayesian belief propagation, remplace propagate_confidence)
#        chroma (vector store embarqué pour memory engine)
#        sentence_transformers (embeddings locaux)
#        langgraph (orchestration pipeline)
#        pydriller (git mining pour drift detection)
#        thompson_sampling (multi-armed bandit pour _decide())
#
#  Ce script :
#    1. Clone (shallow) les repos pertinents
#    2. Filtre pour garder UNIQUEMENT le code utile
#    3. Découpe en archives ZIP de max 19 MB pour upload sur Claude
#
#  Usage :
#     bash harvest_sources_v3.sh                      # full harvest (v2 behavior)
#     bash harvest_sources_v3.sh repo pgmpy langgraph # repos ciblés uniquement
#     bash harvest_sources_v3.sh list                 # liste des repos connus
#     bash harvest_sources_v3.sh [output_dir]         # change l'output dir
# ============================================================================

set -euo pipefail

# ─────────────────────────────────────────────
#  Parse arguments
# ─────────────────────────────────────────────

MODE="full"
REQUESTED_REPOS=()
OUT_DEFAULT="$HOME/BELIEF_SOURCES"
OUT=""

if [ $# -gt 0 ]; then
    case "$1" in
        repo)
            MODE="targeted"
            shift
            if [ $# -eq 0 ]; then
                echo "ERROR: mode 'repo' requires at least one repo name"
                echo "Usage: bash $0 repo <name1> [name2] ..."
                exit 1
            fi
            REQUESTED_REPOS=("$@")
            OUT="${OUT:-$OUT_DEFAULT}"
            ;;
        list)
            MODE="list"
            ;;
        -h|--help)
            grep '^#' "$0" | head -30
            exit 0
            ;;
        *)
            # Assume it's the output directory (v2 behavior)
            OUT="$1"
            ;;
    esac
fi

OUT="${OUT:-$OUT_DEFAULT}"
MAX_MB=19
SPLIT_BYTES=$((MAX_MB * 1024 * 1024))
TMP="$OUT/.tmp_clone"
GIT_TIMEOUT=120

# ─────────────────────────────────────────────
#  Table des repos connus (single source of truth)
#  Format: [name]="repo_url|subdir|exclude_patterns|target_module"
# ─────────────────────────────────────────────

declare -A REPO_TABLE=(
    # ── Section A : sources originales v2 ──
    ["codeql_python"]="https://github.com/github/codeql.git|python/ql/src/Security||security_patterns,semgrep_db"
    ["codeql_dataflow"]="https://github.com/github/codeql.git|python/ql/lib/semmle/python|test|experimental|taint,cross_lang"
    ["semgrep_rules"]="https://github.com/semgrep/semgrep-rules.git||test|apex|elixir|ruby|scala|kotlin|swift|ocaml|terraform|dockerfile|php|csharp|solidity|semgrep_db,security_patterns"
    ["joern_core"]="https://github.com/joernio/joern.git|joern-cli/src|test|cross_language,cfg"
    ["joern_queries"]="https://github.com/joernio/joern.git|querydb|test|cross_language,security_patterns"
    ["pyre_taint"]="https://github.com/facebook/pyre-check.git|stubs/taint||taint,knowledge_base"
    ["pyre_pysa"]="https://github.com/facebook/pyre-check.git|source/interprocedural_analyses/taint|test|taint"
    ["pyre_sapp"]="https://github.com/facebook/pyre-check.git|tools/sapp|test|ui|report_gen,artifacts"
    ["bandit"]="https://github.com/PyCQA/bandit.git|bandit|test|security_patterns,semgrep_db"
    ["dlint"]="https://github.com/dlint-py/dlint.git|dlint|test|security_patterns"
    ["safety_db"]="https://github.com/pyupio/safety-db.git|||cve_correlator,supply_chain"
    ["nuclei_misconfig"]="https://github.com/projectdiscovery/nuclei-templates.git|http/misconfiguration||config_scanner,http_engine"
    ["nuclei_tech"]="https://github.com/projectdiscovery/nuclei-templates.git|http/technologies||http_engine"
    ["git_of_theseus"]="https://github.com/erikbern/git-of-theseus.git|git_of_theseus|test|advanced_drift,drift"
    ["frouros"]="https://github.com/IFCA-Advanced-Computing/frouros.git|frouros|test|advanced_drift,drift"
    # driftgan/DriftSurf supprimé en v3 — URL n'existe pas, frouros couvre le besoin drift.
    ["pyexz3"]="https://github.com/thomasjball/PyExZ3.git||test|symbolic,z3_verifier"
    ["crosshair"]="https://github.com/pschanely/CrossHair.git|crosshair|test|symbolic,formal_verify,property_tester"
    ["z3_playground"]="https://github.com/Z3Prover/z3.git|examples/python||symbolic,z3_verifier"
    ["codegraph"]="https://github.com/xnuinside/codegraph.git||test|dep_graph,graph"
    ["pydeps"]="https://github.com/thebjorn/pydeps.git|pydeps|test|dep_graph"
    ["pyan"]="https://github.com/davidfraser/pyan.git|pyan|test|dep_graph,graph"
    ["importlab"]="https://github.com/google/importlab.git|importlab|test|dep_graph"
    ["modulegraph2"]="https://github.com/ronaldoussoren/modulegraph2.git|modulegraph2|test|dep_graph"
    ["findimports"]="https://github.com/mgedmin/findimports.git||test|dep_graph"
    ["pyt"]="https://github.com/python-security/pyt.git|pyt|test|taint,cfg"
    ["contextgem"]="https://github.com/shcherbak-ai/contextgem.git|contextgem|test|examples|docs|extractor,llm_client,llm_ensemble"
    ["code_analyzer"]="https://github.com/thinmanj/code-analyzer.git||test|examples|extractor,orchestrator"
    ["supply_chain_firewall"]="https://github.com/DataDog/supply-chain-firewall.git||test|integration|supply_chain,cve_correlator"

    # ── Section B : ajouts v3 pour roadmap Phase 3→6 ──
    ["pgmpy"]="https://github.com/pgmpy/pgmpy.git|pgmpy|test|cognitive/belief_graph,propagate_confidence"
    ["chroma"]="https://github.com/chroma-core/chroma.git|chromadb|test|cognitive/memory_engine"
    ["sentence_transformers"]="https://github.com/UKPLab/sentence-transformers.git|sentence_transformers|test|cognitive/memory_engine,embeddings"
    ["langgraph"]="https://github.com/langchain-ai/langgraph.git|libs/langgraph|test|orchestrator,pipeline"
    ["pydriller"]="https://github.com/ishepard/pydriller.git|pydriller|test|temporal,drift"
    ["pybandits"]="https://github.com/PlaytikaOSS/pybandits.git|pybandits|test|cognitive/decide,bandit,thompson"
)

# ─────────────────────────────────────────────
#  Mode : list
# ─────────────────────────────────────────────

if [ "$MODE" = "list" ]; then
    echo "=== Repos connus dans harvest_sources_v3.sh ==="
    echo ""
    printf "  %-26s %-60s %s\n" "NAME" "REPO_URL" "TARGET_MODULE"
    printf "  %-26s %-60s %s\n" "----" "--------" "-------------"
    for name in $(echo "${!REPO_TABLE[@]}" | tr ' ' '\n' | sort); do
        entry="${REPO_TABLE[$name]}"
        url=$(echo "$entry" | cut -d'|' -f1)
        # target is the last field after pipes — simpler: split by |
        IFS='|' read -ra parts <<< "$entry"
        # fields: url | subdir | exclude | target_module
        # note: exclude can itself contain pipes originally — we assume it's safe here (re-encoded with ; if needed)
        target="${parts[${#parts[@]}-1]}"
        printf "  %-26s %-60s %s\n" "$name" "$url" "$target"
    done
    echo ""
    echo "Usage: bash $0 repo <name1> [name2] ..."
    exit 0
fi

# ─────────────────────────────────────────────
#  Validation en mode targeted
# ─────────────────────────────────────────────

if [ "$MODE" = "targeted" ]; then
    for name in "${REQUESTED_REPOS[@]}"; do
        if [ -z "${REPO_TABLE[$name]+x}" ]; then
            echo "ERROR: unknown repo '$name'"
            echo "Run 'bash $0 list' to see available names"
            exit 2
        fi
    done
fi

# ─────────────────────────────────────────────
#  Création de l'arbo
# ─────────────────────────────────────────────

mkdir -p "$OUT" "$TMP"
if [ "$MODE" = "targeted" ]; then
    mkdir -p "$OUT/zips_targeted"
else
    mkdir -p "$OUT/zips"
fi

echo "=============================================="
echo "  BELIEF Source Harvester v3"
echo "  Mode   : $MODE"
echo "  Output : $OUT"
echo "  Max archive : ${MAX_MB} MB"
if [ "$MODE" = "targeted" ]; then
    echo "  Repos  : ${REQUESTED_REPOS[*]}"
fi
echo "=============================================="

# ─────────────────────────────────────────────
#  Fonction clone_filtered (identique à v2)
# ─────────────────────────────────────────────

clone_filtered() {
    local name="$1"
    local repo="$2"
    local subdir="${3:-}"
    local exclude_patterns="${4:-}"

    echo ""
    echo "━━━ [$name] Cloning $repo ━━━"

    local clone_dir="$TMP/$name"
    rm -rf "$clone_dir"

    # GIT_TERMINAL_PROMPT=0 : jamais prompt pour credentials (fail fast)
    # GIT_ASKPASS=/bin/echo : backup si terminal prompt est contourné
    # -c credential.helper= : neutralise les helpers système
    if ! GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=/bin/echo \
            timeout "$GIT_TIMEOUT" git \
            -c credential.helper= \
            -c core.askPass=/bin/echo \
            clone --depth 1 --single-branch \
            "$repo" "$clone_dir" 2>/dev/null; then
        echo "  ⚠ Clone failed/timeout/private for $name, skipping"
        return 1
    fi

    local src_dir="$clone_dir"
    if [ -n "$subdir" ]; then
        src_dir="$clone_dir/$subdir"
        if [ ! -d "$src_dir" ]; then
            echo "  ⚠ Subdir '$subdir' not found in $name — using repo root"
            src_dir="$clone_dir"
        fi
    fi

    local dest="$OUT/raw/$name"
    rm -rf "$dest"
    mkdir -p "$dest"

    cd "$src_dir"
    find . -type f \( \
        -name "*.py" -o \
        -name "*.ql" -o \
        -name "*.qll" -o \
        -name "*.yml" -o \
        -name "*.yaml" -o \
        -name "*.json" -o \
        -name "*.toml" -o \
        -name "*.cfg" -o \
        -name "*.md" -o \
        -name "*.rs" -o \
        -name "*.go" -o \
        -name "*.java" -o \
        -name "*.ts" -o \
        -name "*.js" \
    \) \
    ! -path "*/.git/*" \
    ! -path "*/node_modules/*" \
    ! -path "*/__pycache__/*" \
    ! -path "*/venv/*" \
    ! -path "*/dist/*" \
    ! -path "*/build/*" \
    ! -path "*/.tox/*" \
    ! -path "*/test_data/*" \
    ! -path "*/testdata/*" \
    ! -path "*/fixtures/*" \
    ! -path "*/.mypy_cache/*" \
    ! -path "*/.pytest_cache/*" \
    ! -path "*/vendor/*" \
    ! -path "*/third_party/*" \
    ! -path "*/site-packages/*" \
    ! -path "*/changelog/*" \
    ! -path "*/CHANGELOG*" \
    ! -path "*/.github/workflows/*" \
    | while read -r f; do
        local target="$dest/$f"
        mkdir -p "$(dirname "$target")"
        cp "$f" "$target" 2>/dev/null || true
    done
    cd "$OUT"

    if [ -n "$exclude_patterns" ]; then
        IFS=';' read -ra patterns <<< "$exclude_patterns"
        for pat in "${patterns[@]}"; do
            [ -z "$pat" ] && continue
            find "$dest" -path "*$pat*" -delete 2>/dev/null || true
        done
    fi

    # Supprimer les fichiers > 500KB
    find "$dest" -type f -size +500k -delete 2>/dev/null || true
    # Nettoyer les dossiers vides
    find "$dest" -type d -empty -delete 2>/dev/null || true

    if [ ! -d "$dest" ] || [ -z "$(ls -A "$dest" 2>/dev/null)" ]; then
        echo "  ⚠ $name : aucun fichier utile retenu, skip"
        rm -rf "$dest"
        return 1
    fi

    local size_mb=$(du -sm "$dest" 2>/dev/null | awk '{print $1}')
    local file_count=$(find "$dest" -type f | wc -l)
    echo "  ✓ $name : ${size_mb} MB, ${file_count} fichiers"

    return 0
}

# ─────────────────────────────────────────────
#  Fonction make_split_zip (identique à v2)
# ─────────────────────────────────────────────

make_split_zip() {
    local name="$1"
    local zip_dir="${2:-$OUT/zips}"
    local src_dir="$OUT/raw/$name"

    mkdir -p "$zip_dir"

    if [ ! -d "$src_dir" ]; then
        echo "  ⚠ $src_dir not found, skipping zip"
        return
    fi

    local total_size=$(du -sb "$src_dir" | awk '{print $1}')

    if [ "$total_size" -le "$SPLIT_BYTES" ]; then
        cd "$OUT/raw"
        zip -r -q "$zip_dir/${name}.zip" "$name/"
        local zip_size=$(du -sm "$zip_dir/${name}.zip" | awk '{print $1}')
        echo "  📦 ${name}.zip (${zip_size} MB)"
    else
        echo "  📦 $name dépasse ${MAX_MB} MB, découpage..."

        cd "$src_dir"
        local file_list=$(find . -type f | sort)

        local part=1
        local current_size=0
        local current_files=""
        local max_bytes=$((SPLIT_BYTES - 1024*1024))

        while IFS= read -r filepath; do
            local fsize=$(stat -c%s "$filepath" 2>/dev/null || echo 0)

            if [ $((current_size + fsize)) -gt "$max_bytes" ] && [ -n "$current_files" ]; then
                local part_name=$(printf "${name}_part%02d" "$part")
                echo "$current_files" | tr ' ' '\n' | \
                    zip -q "$zip_dir/${part_name}.zip" -@
                local zs=$(du -sm "$zip_dir/${part_name}.zip" | awk '{print $1}')
                echo "    📦 ${part_name}.zip (${zs} MB)"

                part=$((part + 1))
                current_size=0
                current_files=""
            fi

            current_size=$((current_size + fsize))
            current_files="$current_files $filepath"

        done <<< "$file_list"

        if [ -n "$current_files" ]; then
            local part_name=$(printf "${name}_part%02d" "$part")
            cd "$src_dir"
            echo "$current_files" | tr ' ' '\n' | \
                zip -q "$zip_dir/${part_name}.zip" -@
            local zs=$(du -sm "$zip_dir/${part_name}.zip" 2>/dev/null | awk '{print $1}')
            echo "    📦 ${part_name}.zip (${zs:-<1} MB)"
        fi
    fi

    cd "$OUT"
}

# ─────────────────────────────────────────────
#  Wrapper : clone + zip pour UN repo de la table
# ─────────────────────────────────────────────

harvest_one() {
    local name="$1"
    local zip_dir="${2:-$OUT/zips}"

    local entry="${REPO_TABLE[$name]}"
    # format: url|subdir|exclude|target
    # exclude peut contenir des | → on prend url=part1, subdir=part2,
    # target=dernier, exclude=le reste concaténé avec |
    # Plus simple : on split et on reconstruit
    IFS='|' read -ra parts <<< "$entry"
    local nparts=${#parts[@]}
    local url="${parts[0]}"
    local subdir="${parts[1]}"
    local target="${parts[$((nparts-1))]}"
    local exclude=""
    # exclude = concat parts[2..nparts-2] avec |
    if [ "$nparts" -gt 3 ]; then
        for i in $(seq 2 $((nparts-2))); do
            if [ -z "$exclude" ]; then
                exclude="${parts[$i]}"
            else
                exclude="$exclude;${parts[$i]}"
            fi
        done
    fi

    if clone_filtered "$name" "$url" "$subdir" "$exclude"; then
        make_split_zip "$name" "$zip_dir"
    fi
}

# ─────────────────────────────────────────────
#  Mode : targeted
# ─────────────────────────────────────────────

if [ "$MODE" = "targeted" ]; then
    for name in "${REQUESTED_REPOS[@]}"; do
        harvest_one "$name" "$OUT/zips_targeted"
    done

    echo ""
    echo "━━━ Nettoyage clones temporaires ━━━"
    rm -rf "$TMP"

    echo ""
    echo "━━━ Archives ciblées ━━━"
    echo ""
    for z in "$OUT/zips_targeted"/*.zip; do
        if [ -f "$z" ]; then
            size=$(du -sm "$z" | awk '{print $1}')
            printf "  %-40s %4s MB\n" "$(basename "$z")" "$size"
        fi
    done
    total_zips=$(ls -1 "$OUT/zips_targeted"/*.zip 2>/dev/null | wc -l)
    echo ""
    echo "=============================================="
    echo "  ✅ ${total_zips} archives ciblées créées"
    echo "  📂 Dossier : $OUT/zips_targeted/"
    echo ""
    echo "  Upload directement ces zip(s) sur Claude"
    echo "  pour demander l'intégration copier-coller"
    echo "=============================================="
    exit 0
fi

# ─────────────────────────────────────────────
#  Mode : full (comportement v2 étendu avec les nouveaux repos v3)
# ─────────────────────────────────────────────

echo ""
echo "━━━ Mode FULL : tous les repos de REPO_TABLE ━━━"
echo ""

for name in $(echo "${!REPO_TABLE[@]}" | tr ' ' '\n' | sort); do
    harvest_one "$name" "$OUT/zips"
done

# ─────────────────────────────────────────────
#  Cleanup + résumé
# ─────────────────────────────────────────────

echo ""
echo "━━━ Nettoyage clones temporaires ━━━"
rm -rf "$TMP"

echo ""
echo "━━━ Résumé des sources récupérées ━━━"
echo ""

manifest="$OUT/MANIFEST.csv"
echo "name,size_mb,file_count,target_belief_module" > "$manifest"

for d in "$OUT/raw"/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$d")
    size=$(du -sm "$d" 2>/dev/null | awk '{print $1}')
    count=$(find "$d" -type f | wc -l)
    entry="${REPO_TABLE[$name]:-}"
    if [ -n "$entry" ]; then
        IFS='|' read -ra parts <<< "$entry"
        target="${parts[${#parts[@]}-1]}"
    else
        target="unknown"
    fi
    printf "  %-25s %4s MB  %5d fichiers  →  %s\n" "$name" "$size" "$count" "$target"
    echo "${name},${size},${count},${target}" >> "$manifest"
done

total=$(du -sm "$OUT/raw" 2>/dev/null | awk '{print $1}')
echo ""
echo "  TOTAL : ${total} MB"
echo "  Manifest : $manifest"
echo ""

cd "$OUT"
zip -q "$OUT/zips/_MANIFEST.zip" "MANIFEST.csv" 2>/dev/null || true

echo ""
echo "━━━ Archives finales ━━━"
echo ""
for z in "$OUT/zips"/*.zip; do
    if [ -f "$z" ]; then
        size=$(du -sm "$z" | awk '{print $1}')
        printf "  %-40s %4s MB\n" "$(basename "$z")" "$size"
    fi
done

total_zips=$(ls -1 "$OUT/zips"/*.zip 2>/dev/null | wc -l)
total_zip_size=$(du -sm "$OUT/zips" 2>/dev/null | awk '{print $1}')

echo ""
echo "=============================================="
echo "  ✅ ${total_zips} archives créées (${total_zip_size} MB total)"
echo "  📂 Dossier : $OUT/zips/"
echo ""
echo "  Upload ensuite chaque .zip sur Claude"
echo "  (max ${MAX_MB} MB chacun)"
echo "  Commence par _MANIFEST.zip → liste tout ce qu'il y a"
echo ""
echo "  Ou, pour un repo ciblé :"
echo "     bash $0 repo <name>"
echo "=============================================="
