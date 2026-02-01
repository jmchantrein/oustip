# AGENTS.md - OustIP

> Regles fondamentales pour tous les agents IA travaillant sur ce projet.

## Premiere action obligatoire

**Avant toute action, lire `.ai/MEMORY.md`** pour :
- Comprendre le contexte en cours
- Connaitre les decisions passees
- Eviter de repeter les erreurs

## Identite du projet

- **Nom** : OustIP
- **Description** : Gestionnaire de blocklists IP pour passerelles Linux
- **Langage** : Rust (edition 2021, rust-version 1.75)
- **Licence** : AGPL-3.0-or-later
- **Paradigme** : Spec-driven (specifications avant code)
- **Documentation** : Bilingue (EN principal, FR miroir)

## Regle 0 : Honnetete

- Dire "je ne sais pas" quand c'est le cas
- Ne jamais inventer de fonctionnalites ou APIs
- Signaler les incertitudes explicitement
- Admettre les erreurs sans chercher a les cacher

## Regle 1 : Etat de l'art et consensus

Avant toute implementation :
1. Rechercher les bonnes pratiques actuelles
2. Verifier s'il existe un consensus etabli
3. Consulter la documentation officielle des outils utilises
4. Privilegier les solutions eprouvees aux innovations risquees

## Regle 2 : Developpement dirige (Spec-driven)

1. **Specification** : Definir clairement ce qui doit etre fait
2. **Implementation** : Coder uniquement ce qui est specifie
3. **Validation** : Verifier que l'implementation correspond a la spec
4. **Documentation** : Mettre a jour la doc si necessaire

Ne jamais coder avant d'avoir compris et valide les specifications.

## Regle 3 : Securite

### Toujours
- Valider toutes les entrees utilisateur
- Utiliser des operations atomiques pour les fichiers d'etat
- Propager les erreurs avec `?` ou `Result`
- Limiter les ressources (taille, temps, memoire)

### Jamais
- `unwrap()` ou `expect()` sans justification documentee
- `shell=true` pour executer des commandes
- Logger des secrets ou credentials
- Ignorer les warnings de securite

### Demander avant
- Utiliser `unsafe`
- Ajouter une dependance avec fonctionnalites reseau/systeme
- Modifier la validation des entrees

## Regle 4 : DRY et KISS

- **DRY** : Ne pas repeter le code - factoriser
- **KISS** : Solution la plus simple qui fonctionne
- Pas de sur-ingenierie ou d'abstraction prematuree
- Preferer la lisibilite a la cleverness

## Regle 5 : Todo list

Utiliser une todo list pour :
- Planifier les taches complexes (3+ etapes)
- Suivre la progression
- Ne rien oublier
- Communiquer l'avancement

Mettre a jour immediatement quand une tache est terminee.

## Regle 6 : Organisation des fichiers

```
src/
├── main.rs                 # Point d'entree, dispatch CLI
├── lib.rs                  # Exports publics
├── cli.rs                  # Definition CLI (Clap)
├── config.rs               # Chargement/validation config
├── commands/               # Sous-commandes
│   ├── mod.rs
│   ├── update.rs           # Commande principale
│   ├── diagnose/           # Diagnostics
│   └── ...
├── enforcer/               # Backends firewall
│   ├── mod.rs
│   ├── nftables.rs
│   └── iptables.rs
└── ...

.ai/                        # Architecture IA
├── skills/                 # Definitions d'agents
├── commands/               # Reference rapide
├── MEMORY.md               # Memoire persistante
└── generate.sh             # Generateur multi-plateforme

docs/                       # Documentation
tests/                      # Tests integration/robustesse
benches/                    # Benchmarks
```

## Regle 7 : Gestion des agents

Les skills sont definis dans `.ai/skills/*.yaml`.

Agents disponibles :
- `project-assistant` : Assistant principal
- `rust-expert` : Revue code Rust
- `security-reviewer` : Audit securite
- `inclusivity-reviewer` : Ecriture inclusive
- `translator` : Traduction EN-FR
- `memory-keeper` : Gestion memoire
- `workflow-orchestrator` : Orchestration

Consulter le skill approprie selon la tache.

## Regle 8 : Auto-amelioration

Proposer des ameliorations quand :
- Un pattern se repete (factorisation)
- Une meilleure pratique existe
- La documentation est obsolete
- Un bug revele un probleme systemique

Ne pas implementer sans validation.

## Regle 9 : Checklist avant commit

- [ ] `cargo fmt` execute
- [ ] `cargo clippy -- -D warnings` passe
- [ ] `cargo test` passe
- [ ] Pas de `unwrap()` non justifie
- [ ] Documentation mise a jour si API modifiee
- [ ] Commit message suit les conventions (feat/fix/docs/...)

## Regle 10 : Conventions d'ecriture et inclusivite

### Francais
- Utiliser le point median : utilisateur·ice, developpeur·euse
- Eviter le masculin generique
- Langage non capacitiste (pas de "sourd a", "aveugle a")

### Code
- Noms en anglais
- Commentaires techniques en anglais
- Documentation utilisateur bilingue

### Messages de commit
```
type(scope): description

[body optionnel]

[footer optionnel]
```

Types : feat, fix, docs, style, refactor, test, chore

## Regle 11 : Auto-relecture

Avant de soumettre du code :
1. Relire le diff complet
2. Verifier la coherence avec le reste du code
3. S'assurer que les tests couvrent les cas limites
4. Valider que la doc est a jour

## Regle 12 : Memoire persistante

Mettre a jour `.ai/MEMORY.md` apres :
- Une decision technique importante
- La resolution d'un bug complexe
- L'ajout d'une nouvelle fonctionnalite
- Une lecon apprise

Format : tableau avec date, decision, raison.

## Regle 13 : Langue et traduction

- **Code** : Anglais
- **Commits** : Anglais
- **Documentation technique** : Anglais (principal) + Francais (miroir)
- **Documentation utilisateur** : Bilingue avec liens croises
- **MEMORY.md** : Francais (langue du projet IA)

Synchroniser les versions apres chaque modification majeure.

## Regle 14 : Workflows de communication

### Avant de modifier
1. Lire les fichiers concernes
2. Comprendre le contexte existant
3. Verifier `.ai/MEMORY.md`

### Apres modification
1. Tester les changements
2. Mettre a jour la documentation si necessaire
3. Notifier `memory-keeper` si decision importante

### En cas de doute
1. Demander clarification
2. Proposer des options avec trade-offs
3. Ne pas deviner les intentions

## Regle 15 : Actions post-revue (OBLIGATOIRE)

Apres chaque revue de code ou session de travail significative :

### 1. Mettre a jour MEMORY.md
- Ajouter une nouvelle section avec la date
- Documenter les corrections appliquees
- Lister les fichiers modifies
- Noter les scores/metriques si applicable

### 2. Synchroniser la documentation
- Verifier que README.md/README_FR.md sont a jour
- Verifier que docs/ARCHITECTURE.md reflete le code
- Documenter les nouvelles commandes/fonctionnalites

### 3. Marquer les taches terminees
- Cocher les items dans "A faire" de MEMORY.md
- Ajouter la date de completion

### 4. Template de notes de session
```markdown
### YYYY-MM-DD - [Description session]

**Objectif** : [Description]

**Corrections appliquees** :
- [Liste des corrections]

**Fichiers modifies** :
- [Liste des fichiers]

**Observations** :
- [Notes importantes]
```

Cette regle garantit la tracabilite et la continuite entre sessions.

---

## References

- [README.md](README.md) - Documentation principale
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) - Architecture detaillee
- [.ai/MEMORY.md](.ai/MEMORY.md) - Contexte et decisions
- [.ai/skills/](.ai/skills/) - Definitions des agents

---

*Genere par l'architecture IA hybride v1.0.0*
