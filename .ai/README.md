# .ai/ - Architecture IA Hybride

> Source unique pour les definitions d'agents et configurations IA multi-plateforme.

## Structure

```
.ai/
├── skills/                     # Definitions YAML des agents (source unique)
│   ├── _TEMPLATE.yaml          # Template pour nouveaux skills
│   ├── project-assistant.yaml  # Assistant principal du projet
│   ├── inclusivity-reviewer.yaml
│   ├── memory-keeper.yaml
│   ├── workflow-orchestrator.yaml
│   ├── translator.yaml
│   ├── rust-expert.yaml
│   └── security-reviewer.yaml
├── commands/
│   └── quick-reference.md      # Reference rapide des commandes
├── plans/                      # Plans d'implementation
├── legacy-backup/              # Fichiers de config IA originaux (backup)
├── MEMORY.md                   # Memoire persistante entre sessions
├── sources.yaml                # Sources de donnees et references
├── VERSION                     # Version de l'architecture (pour generate.sh)
├── README.md                   # Ce fichier
└── generate.sh                 # Script de generation multi-plateforme
```

## Utilisation

### Regenerer les fichiers de configuration

```bash
.ai/generate.sh          # Regenere uniquement si VERSION a change
.ai/generate.sh --force  # Force la regeneration
```

### Ajouter un nouveau skill

1. Copier `.ai/skills/_TEMPLATE.yaml`
2. Renommer et personnaliser
3. Executer `.ai/generate.sh --force`

## Fichiers generes

Le script `generate.sh` produit :

| Plateforme | Fichiers |
|------------|----------|
| AGENTS.md (standard) | `AGENTS.md` (racine) |
| Claude Code | `CLAUDE.md`, `.claude/agents/*.md` |
| OpenCode | `.opencode/agent/*.md` |
| Ollama | `ollama/Modelfile.*`, `ollama/create-all.sh` |
| Continue.dev | `.continuerc.json` |
| Aider | `.aider.conf.yml` |
| Cursor | `.cursorrules` |
| Codex | `.codex/agents/*.md` |

## Regles fondamentales

Toutes les regles sont definies dans `AGENTS.md` a la racine du projet.
Les agents doivent lire `.ai/MEMORY.md` en premier pour le contexte.

## Maintenance

- Mettre a jour `.ai/MEMORY.md` apres chaque session significative
- Incrementer `.ai/VERSION` pour forcer la regeneration
- Les modifications de skills ne prennent effet qu'apres `generate.sh`
