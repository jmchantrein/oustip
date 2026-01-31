# MEMORY.md - Memoire persistante OustIP

> Contexte et decisions pour la continuite entre sessions IA.

## Identite du projet

| Attribut | Valeur |
|----------|--------|
| Nom | OustIP |
| Version | 0.2.0 |
| Langage | Rust (edition 2021) |
| Rust minimum | 1.75 |
| Licence | AGPL-3.0-or-later |
| Repository | https://github.com/jmchantrein/oustip |
| Statut | En developpement (pas encore production) |

## Preferences utilisateur·ice

- Paradigme : Spec-driven (specifications avant code)
- Environnement : Hybride (cloud + local)
- Documentation : Bilingue EN/FR avec liens croises
- Ecriture : Inclusive en francais (point median)
- Outils IA : Couverture large souhaitee

## Decisions techniques

| Date | Decision | Raison | Impact |
|------|----------|--------|--------|
| 2026-01-31 | Migration vers architecture IA hybride | Centralisation des configs, multi-plateforme | Creation `.ai/`, AGENTS.md |
| 2026-01-31 | Paradigme spec-driven | Objectif production, tracabilite | Specifications avant implementation |
| 2026-01-31 | nftables par defaut | Performance O(1) avec sets | Backend prioritaire |
| 2026-01-31 | rustls au lieu d'OpenSSL | Moins de dependances systeme | Portabilite accrue |
| 2026-01-31 | serde-saphyr pour YAML | Support YAML moderne | Remplacement de serde_yaml |

## Historique des evolutions

### v0.2.0 (2026-01-31)
- Ajout commande `diagnose` pour tests runtime
- Architecture IA hybride mise en place
- Documentation architecture detaillee

### v0.1.0 (2026-01-31)
- Version initiale
- Support nftables/iptables
- Systeme de presets heritables
- Alertes multi-canal (Gotify, email, webhook)
- Configuration par interface
- Internationalisation EN/FR

## Lecons apprises

| Date | Lecon | Contexte |
|------|-------|----------|
| 2026-01-31 | Documenter les commandes des leur ajout | `diagnose` non documente dans README |
| 2026-01-31 | Synchroniser ARCHITECTURE.md avec le code | Structure commands/ evoluee |

## Contexte en cours

### En cours
- Migration architecture IA hybride (cette session)
- Documentation a synchroniser avec le code

### A faire
- [ ] Mettre a jour docs/ARCHITECTURE.md (ajouter `diagnose`)
- [ ] Mettre a jour README.md et README_FR.md (ajouter `diagnose`)
- [ ] Valider que tous les tests passent
- [ ] Preparer pour production

### Bloque
- Aucun blocage actuel

## Agents disponibles

| Agent | Description | Declenchement |
|-------|-------------|---------------|
| project-assistant | Assistant principal | Modifications src/*.rs |
| rust-expert | Revue code Rust | Performance, idiomes |
| security-reviewer | Audit securite | Validation, injection |
| inclusivity-reviewer | Ecriture inclusive | Docs FR |
| translator | Traduction EN-FR | Sync docs |
| memory-keeper | Gestion memoire | Decisions importantes |
| workflow-orchestrator | Orchestration | Release, refactoring |

## Notes de session

### 2026-01-31 - Migration IA hybride

**Objectif** : Migrer vers architecture IA hybride multi-plateforme

**Actions realisees** :
1. Analyse du projet existant (aucun fichier IA legacy)
2. Creation structure `.ai/` complete
3. Definition de 7 skills :
   - project-assistant, rust-expert, security-reviewer
   - inclusivity-reviewer, translator
   - memory-keeper, workflow-orchestrator
4. Creation AGENTS.md avec 15 regles fondamentales
5. Creation MEMORY.md (ce fichier)
6. Creation generate.sh (generateur multi-plateforme)
7. Generation des fichiers pour 7 plateformes
8. Documentation de l'architecture dans README.md et README_FR.md
9. Validation : tous les tests passent

**Fichiers crees** :
- `.ai/` (structure complete)
- `AGENTS.md`, `CLAUDE.md`
- `.claude/agents/*.md`
- `.opencode/agent/*.md`
- `ollama/Modelfile.*`, `ollama/create-all.sh`
- `.continuerc.json`, `.aider.conf.yml`, `.cursorrules`
- `.codex/agents/*.md`

**Observations** :
- Projet propre, pas de fichiers IA legacy a migrer
- Documentation bilingue conservee au format actuel (`README_FR.md`)
- `diagnose` non documente (a faire)
- docs/ARCHITECTURE.md potentiellement desynchronise (a verifier)

**Prochaines etapes recommandees** :
- [ ] Documenter la commande `diagnose` dans README
- [ ] Verifier/mettre a jour docs/ARCHITECTURE.md
- [ ] Tester avec les differentes plateformes IA
- [ ] Preparer pour production

---

*Derniere mise a jour : 2026-01-31*
