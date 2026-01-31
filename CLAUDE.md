# CLAUDE.md

> Ce fichier redirige vers AGENTS.md pour la compatibilite Claude Code.

Voir [AGENTS.md](AGENTS.md) pour les regles completes.

## Rappel rapide

1. **Premiere action** : Lire `.ai/MEMORY.md`
2. **Paradigme** : Spec-driven (specifications avant code)
3. **Securite** : Valider les entrees, pas de `unwrap()` non justifie
4. **Qualite** : `cargo fmt` + `cargo clippy` + `cargo test` avant commit
5. **Documentation** : Bilingue (EN + FR)

## Fichiers cles

| Fichier | Description |
|---------|-------------|
| [AGENTS.md](AGENTS.md) | Regles completes |
| [.ai/MEMORY.md](.ai/MEMORY.md) | Contexte et decisions |
| [.ai/skills/](.ai/skills/) | Definitions des agents |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Architecture technique |

## Commandes frequentes

```bash
cargo fmt && cargo clippy && cargo test  # Avant commit
.ai/generate.sh --force                   # Regenerer configs IA
```

---

*Pointeur vers AGENTS.md - Architecture IA hybride v1.0.0*
