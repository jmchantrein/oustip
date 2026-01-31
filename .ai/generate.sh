#!/bin/bash
# generate.sh - Generateur de configurations IA multi-plateforme
#
# Usage:
#   .ai/generate.sh          # Regenere uniquement si VERSION a change
#   .ai/generate.sh --force  # Force la regeneration
#
# Ce script genere les fichiers de configuration pour :
# - Claude Code (.claude/agents/)
# - OpenCode (.opencode/agent/)
# - Ollama (ollama/Modelfile.*)
# - Continue.dev (.continuerc.json)
# - Aider (.aider.conf.yml)
# - Cursor (.cursorrules)
# - Codex (.codex/agents/)

set -euo pipefail

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Repertoire du script
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Fichiers de version
VERSION_FILE="$SCRIPT_DIR/VERSION"
GENERATED_VERSION_FILE="$SCRIPT_DIR/.generated-version"

# Parse les arguments
FORCE=false
VERBOSE=false
for arg in "$@"; do
    case $arg in
        --force|-f)
            FORCE=true
            ;;
        --verbose|-v)
            VERBOSE=true
            ;;
        --help|-h)
            echo "Usage: $0 [--force] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --force, -f    Force regeneration even if VERSION unchanged"
            echo "  --verbose, -v  Show detailed output"
            echo "  --help, -h     Show this help"
            exit 0
            ;;
    esac
done

# Fonctions utilitaires
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_verbose() {
    if $VERBOSE; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Verifie si la regeneration est necessaire
check_version() {
    if $FORCE; then
        log_info "Regeneration forcee (--force)"
        return 0
    fi

    if [[ ! -f "$VERSION_FILE" ]]; then
        log_error "VERSION file not found: $VERSION_FILE"
        exit 1
    fi

    local current_version
    current_version=$(cat "$VERSION_FILE")

    if [[ -f "$GENERATED_VERSION_FILE" ]]; then
        local generated_version
        generated_version=$(cat "$GENERATED_VERSION_FILE")

        if [[ "$current_version" == "$generated_version" ]]; then
            log_info "Version unchanged ($current_version). Use --force to regenerate."
            exit 0
        fi
        log_info "Version changed: $generated_version -> $current_version"
    else
        log_info "First generation (version $current_version)"
    fi
}

# Extrait une valeur d'un fichier YAML (simple, sans dependances)
# Usage: yaml_get "file.yaml" "key"
yaml_get() {
    local file="$1"
    local key="$2"
    grep -E "^${key}:" "$file" 2>/dev/null | sed -E "s/^${key}:\s*//" | sed 's/^"//' | sed 's/"$//' | head -1 || echo ""
}

# Extrait la description EN d'un fichier skill YAML
# Usage: yaml_get_description "file.yaml"
yaml_get_description() {
    local file="$1"
    # Look for "en:" under description block
    awk '
        /^description:/ { in_desc=1; next }
        in_desc && /^[a-z_]+:/ && !/^\s/ { in_desc=0 }
        in_desc && /en:/ { gsub(/.*en:\s*"?/, ""); gsub(/"$/, ""); print; exit }
    ' "$file" || echo ""
}

# Extrait le contenu multiligne d'un bloc YAML (persona, etc.)
# Usage: yaml_get_block "file.yaml" "key"
yaml_get_block() {
    local file="$1"
    local key="$2"
    awk -v key="$key" '
        $0 ~ "^"key":.*\\|" { found=1; next }
        found && /^[a-z_]+:/ { found=0 }
        found && /^\s+/ { gsub(/^  /, ""); print }
    ' "$file" || echo ""
}

# Liste tous les skills
list_skills() {
    find "$SCRIPT_DIR/skills" -name "*.yaml" ! -name "_TEMPLATE.yaml" -type f 2>/dev/null | sort
}

# Cree les repertoires necessaires
create_directories() {
    log_info "Creating directories..."
    mkdir -p "$PROJECT_DIR/.claude/agents"
    mkdir -p "$PROJECT_DIR/.opencode/agent"
    mkdir -p "$PROJECT_DIR/ollama"
    mkdir -p "$PROJECT_DIR/.codex/agents"
    log_success "Directories created"
}

# Genere les fichiers Claude Code
generate_claude() {
    log_info "Generating Claude Code files..."

    for skill_file in $(list_skills); do
        local name
        name=$(yaml_get "$skill_file" "name")
        local desc_en
        desc_en=$(yaml_get_description "$skill_file")

        if [[ -z "$name" ]]; then
            name=$(basename "$skill_file" .yaml)
        fi

        log_verbose "  Processing: $name"

        local persona
        persona=$(yaml_get_block "$skill_file" "persona")

        cat > "$PROJECT_DIR/.claude/agents/${name}.md" << EOF
# ${name}

${desc_en:-Agent for $name}

## Instructions

${persona:-See .ai/skills/${name}.yaml for full configuration.}

## Context

- Read \`.ai/MEMORY.md\` first for project context
- Follow rules in \`AGENTS.md\`
- This agent is part of the OustIP hybrid AI architecture
EOF
    done

    log_success "Claude Code files generated"
}

# Genere les fichiers OpenCode
generate_opencode() {
    log_info "Generating OpenCode files..."

    for skill_file in $(list_skills); do
        local name
        name=$(yaml_get "$skill_file" "name")

        if [[ -z "$name" ]]; then
            name=$(basename "$skill_file" .yaml)
        fi

        local persona
        persona=$(yaml_get_block "$skill_file" "persona")

        cat > "$PROJECT_DIR/.opencode/agent/${name}.md" << EOF
# ${name}

${persona:-See .ai/skills/${name}.yaml for configuration.}

---
Source: .ai/skills/${name}.yaml
EOF
    done

    log_success "OpenCode files generated"
}

# Genere les Modelfiles Ollama
generate_ollama() {
    log_info "Generating Ollama Modelfiles..."

    local create_script="$PROJECT_DIR/ollama/create-all.sh"

    cat > "$create_script" << 'EOF'
#!/bin/bash
# Create all Ollama models from Modelfiles
# Generated by .ai/generate.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

for modelfile in "$SCRIPT_DIR"/Modelfile.*; do
    if [[ -f "$modelfile" ]]; then
        name=$(basename "$modelfile" | sed 's/Modelfile\.//')
        echo "Creating model: oustip-$name"
        ollama create "oustip-$name" -f "$modelfile"
    fi
done

echo "All models created!"
EOF
    chmod +x "$create_script"

    for skill_file in $(list_skills); do
        local name
        name=$(yaml_get "$skill_file" "name")

        if [[ -z "$name" ]]; then
            name=$(basename "$skill_file" .yaml)
        fi

        local persona
        persona=$(yaml_get_block "$skill_file" "persona")

        cat > "$PROJECT_DIR/ollama/Modelfile.${name}" << EOF
# Modelfile for ${name}
# Generated by .ai/generate.sh

FROM llama3.2

PARAMETER temperature 0.3
PARAMETER num_ctx 8192

SYSTEM """
${persona:-You are an AI assistant for the OustIP project.}

Project: OustIP - IP Blocklist Manager for Linux Gateways
Language: Rust (edition 2021)
License: AGPL-3.0-or-later

Always read .ai/MEMORY.md first for context.
Follow the rules in AGENTS.md.
"""
EOF
    done

    log_success "Ollama Modelfiles generated"
}

# Genere .continuerc.json
generate_continue() {
    log_info "Generating Continue.dev config..."

    local skills_json="["
    local first=true

    for skill_file in $(list_skills); do
        local name
        name=$(yaml_get "$skill_file" "name")

        if [[ -z "$name" ]]; then
            name=$(basename "$skill_file" .yaml)
        fi

        if $first; then
            first=false
        else
            skills_json+=","
        fi

        skills_json+="\"$name\""
    done
    skills_json+="]"

    cat > "$PROJECT_DIR/.continuerc.json" << EOF
{
  "\$schema": "https://continue.dev/schema.json",
  "name": "OustIP",
  "description": "IP Blocklist Manager for Linux Gateways",
  "contextProviders": [
    {
      "name": "file",
      "params": {
        "defaultFiles": [
          ".ai/MEMORY.md",
          "AGENTS.md",
          "docs/ARCHITECTURE.md"
        ]
      }
    }
  ],
  "customCommands": [
    {
      "name": "memory",
      "description": "Read project memory",
      "prompt": "Read .ai/MEMORY.md and summarize the current context."
    },
    {
      "name": "rules",
      "description": "Show project rules",
      "prompt": "Read AGENTS.md and summarize the key rules."
    }
  ],
  "slashCommands": [],
  "models": [],
  "_skills": ${skills_json},
  "_generated": "$(date -Iseconds)",
  "_version": "$(cat "$VERSION_FILE")"
}
EOF

    log_success "Continue.dev config generated"
}

# Genere .aider.conf.yml
generate_aider() {
    log_info "Generating Aider config..."

    cat > "$PROJECT_DIR/.aider.conf.yml" << EOF
# Aider configuration for OustIP
# Generated by .ai/generate.sh

# Read these files for context
read:
  - .ai/MEMORY.md
  - AGENTS.md
  - docs/ARCHITECTURE.md
  - README.md

# Auto-commit settings
auto-commits: true
dirty-commits: false

# Linting
lint-cmd: "cargo fmt --check && cargo clippy -- -D warnings"
auto-lint: true

# Testing
test-cmd: "cargo test"
auto-test: false

# Model settings (adjust as needed)
# model: claude-3-5-sonnet-20241022

# Git settings
attribute-author: true
attribute-committer: true

# Generated metadata
# version: $(cat "$VERSION_FILE")
# generated: $(date -Iseconds)
EOF

    log_success "Aider config generated"
}

# Genere .cursorrules
generate_cursor() {
    log_info "Generating Cursor rules..."

    cat > "$PROJECT_DIR/.cursorrules" << EOF
# Cursor Rules for OustIP
# Generated by .ai/generate.sh

## Project Context

You are working on OustIP, an IP Blocklist Manager for Linux Gateways written in Rust.

## First Action

Always read \`.ai/MEMORY.md\` first for project context and past decisions.

## Key Rules

1. **Security First**: Validate all inputs, no unwrap() without justification
2. **Spec-Driven**: Understand specifications before implementing
3. **Quality**: Run cargo fmt, clippy, and tests before committing
4. **Bilingual**: Documentation in EN (primary) and FR (mirror)
5. **Inclusive**: Use inclusive writing in French (point median)

## Code Style

- Rust edition 2021, minimum version 1.75
- Use Result/? for error handling, not unwrap()
- Prefer &str over String where possible
- Document with /// not //

## Commands

\`\`\`bash
cargo fmt && cargo clippy -- -D warnings && cargo test
\`\`\`

## Files to Reference

- AGENTS.md - Complete rules
- .ai/MEMORY.md - Context and decisions
- docs/ARCHITECTURE.md - Technical architecture

## Never

- Use shell=true for command execution
- Log secrets or credentials
- Ignore security warnings
- Push to main without review

---
Generated: $(date -Iseconds)
Version: $(cat "$VERSION_FILE")
EOF

    log_success "Cursor rules generated"
}

# Genere les fichiers Codex
generate_codex() {
    log_info "Generating Codex files..."

    for skill_file in $(list_skills); do
        local name
        name=$(yaml_get "$skill_file" "name")

        if [[ -z "$name" ]]; then
            name=$(basename "$skill_file" .yaml)
        fi

        local persona
        persona=$(yaml_get_block "$skill_file" "persona")

        cat > "$PROJECT_DIR/.codex/agents/${name}.md" << EOF
# ${name}

${persona:-See .ai/skills/${name}.yaml for configuration.}

## Project

OustIP - IP Blocklist Manager for Linux Gateways

## Context Files

- .ai/MEMORY.md
- AGENTS.md
- docs/ARCHITECTURE.md
EOF
    done

    log_success "Codex files generated"
}

# Sauvegarde la version generee
save_generated_version() {
    cp "$VERSION_FILE" "$GENERATED_VERSION_FILE"
    log_success "Version saved to .generated-version"
}

# Main
main() {
    echo ""
    echo "=================================================="
    echo "  OustIP - AI Configuration Generator"
    echo "=================================================="
    echo ""

    cd "$PROJECT_DIR"

    check_version
    create_directories

    echo ""
    generate_claude
    generate_opencode
    generate_ollama
    generate_continue
    generate_aider
    generate_cursor
    generate_codex

    save_generated_version

    echo ""
    echo "=================================================="
    log_success "All configurations generated successfully!"
    echo "=================================================="
    echo ""
    echo "Generated files:"
    echo "  - .claude/agents/*.md"
    echo "  - .opencode/agent/*.md"
    echo "  - ollama/Modelfile.*"
    echo "  - ollama/create-all.sh"
    echo "  - .continuerc.json"
    echo "  - .aider.conf.yml"
    echo "  - .cursorrules"
    echo "  - .codex/agents/*.md"
    echo ""
}

main "$@"
