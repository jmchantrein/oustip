# MEMORY.md - Memoire persistante OustIP

> Contexte et decisions pour la continuite entre sessions IA.

## Identite du projet

| Attribut | Valeur |
|----------|--------|
| Nom | OustIP |
| Version | 0.3.0 |
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
- [x] Mettre a jour docs/ARCHITECTURE.md (ajouter `diagnose`) ✅ 2026-01-31
- [x] Mettre a jour README.md et README_FR.md (ajouter `diagnose`) ✅ 2026-01-31
- [x] Valider que tous les tests passent ✅ 2026-01-31
- [ ] Preparer pour production
- [ ] Tester avec les differentes plateformes IA

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
- [x] Documenter la commande `diagnose` dans README ✅ 2026-01-31
- [x] Verifier/mettre a jour docs/ARCHITECTURE.md ✅ 2026-01-31
- [ ] Tester avec les differentes plateformes IA
- [ ] Preparer pour production

---

### 2026-01-31 - Revue de code approfondie (workflow full_review)

**Objectif** : Revue de code orchestree par workflow-orchestrator avec 3 agents en parallele

**Agents utilises** :
1. rust-expert : revue idiomes Rust, performance, gestion d'erreurs
2. security-reviewer : audit securite, vulnerabilites, injections
3. inclusivity-reviewer : ecriture inclusive documentation FR

**Corrections securite appliquees** :
- Ajout timeout 30s sur `exec_nft_script` (DoS protection)
- Ajout `canonicalize()` pour protection path traversal
- Validation noms interface (alphanumerique, max 15 chars)

**Corrections qualite Rust** :
- Suppression fuite memoire `leak()` dans `find_command()`
- Remplacement `unwrap()` par `expect()` avec justification

**Corrections documentation** :
- 24+ accents francais corriges dans README_FR.md
- 2 points medians ajoutes dans skills YAML
- Commande `diagnose` documentee dans README.md, README_FR.md, ARCHITECTURE.md

**Fichiers modifies** :
- `src/enforcer/mod.rs` (leak fix)
- `src/enforcer/nftables.rs` (timeout)
- `src/config.rs` (canonicalize + validation interface)
- `src/validation.rs` (expect)
- `README_FR.md` (accents + diagnose)
- `README.md` (diagnose)
- `docs/ARCHITECTURE.md` (diagnose)
- `.ai/skills/security-reviewer.yaml` (point median)
- `.ai/skills/inclusivity-reviewer.yaml` (point median)

**Score securite** : 7.5/10 → 8.5/10 (amelioration)

---

*Derniere mise a jour : 2026-01-31*
