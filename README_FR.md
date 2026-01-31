# OustIP

[![CI](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml/badge.svg)](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml)
[![Release](https://github.com/jmchantrein/oustip/actions/workflows/release.yml/badge.svg)](https://github.com/jmchantrein/oustip/actions/workflows/release.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

> [!WARNING]
> Ce projet est actuellement en cours de développement. Les fonctionnalités peuvent changer et le logiciel n'est pas encore prêt pour une utilisation en production.

**Gestionnaire de Blocklists IP pour Passerelles Linux**

> *"Oust !"* — Interjection française signifiant "Dehors !", "Du balai !"

OustIP est un outil haute performance pour bloquer les IPs malveillantes sur les passerelles et routeurs Linux. Écrit en Rust pour la sécurité mémoire, zéro pause de garbage collection, et une surface d'attaque minimale.

[English Documentation](README.md) | [Documentation API](https://jmchantrein.github.io/oustip/)

## Fonctionnalités

- **Haute Performance** - Traitement de millions d'IPs avec une latence minimale (auto-détection nftables/iptables)
- **Sécurité Mémoire** - Écrit en Rust avec des garanties à la compilation
- **Simple** - Installation et configuration en 5 minutes
- **Non-Intrusif** - Ne modifie jamais les règles de pare-feu existantes
- **Flexible** - Supporte nftables (par défaut) et iptables
- **Agrégation Intelligente** - Optimisation CIDR pour réduire le nombre de règles
- **Détection des Chevauchements** - Détection automatique des chevauchements allow+block avec résolution DNS
- **Auto-Allowlist** - Liste blanche automatique des fournisseurs CDN (Cloudflare, GitHub, AWS, GCP, Fastly)
- **Alertes** - Notifications via Gotify, email et webhook
- **Bilingue** - Interface en anglais et français
- **Securise** - Support des variables d'environnement pour les identifiants, validation des entrées, operations atomiques

## Démarrage Rapide

### Installation

```bash
# Télécharger le binaire
curl -sSL https://github.com/jmchantrein/oustip/releases/latest/download/oustip-linux-amd64 \
    -o /usr/local/sbin/oustip
chmod +x /usr/local/sbin/oustip

# Installer (crée la config, le service et le timer systemd)
sudo oustip install

# Modifier la configuration (optionnel)
sudo vim /etc/oustip/config.yaml

# Appliquer les règles
sudo oustip update

# Vérifier le statut
oustip status
```

### Docker

```bash
docker pull jmchantrein/oustip:latest
docker run --rm --cap-add NET_ADMIN --network host jmchantrein/oustip update
```

Ou avec docker-compose :

```yaml
version: '3.8'
services:
  oustip:
    image: jmchantrein/oustip:latest
    cap_add:
      - NET_ADMIN
    network_mode: host
    volumes:
      - ./config.yaml:/etc/oustip/config.yaml:ro
    command: ["update"]
```

## Utilisation

```bash
# Commandes principales
oustip install                   # Installer OustIP (interactif)
oustip install --headless        # Installer avec auto-détection des interfaces
oustip install --preset paranoid # Installer avec un preset spécifique
oustip install --config-file /chemin/vers/config.yaml  # Installer avec config existante
oustip update                    # Mise a jour complete: fetch listes + appliquer règles
oustip update presets            # Recharger les definitions de presets.yaml
oustip update lists              # Télécharger blocklists et allowlists
oustip update config             # Recharger config.yaml et appliquer les règles pare-feu
oustip update --dry-run          # Simulation: telecharger sans appliquer les règles
oustip stats                     # Afficher les statistiques de blocage
oustip status                    # Afficher le statut actuel

# Détection d'interfaces
oustip interfaces detect         # Détecter les interfaces reseau et suggerer les modes

# Gestion des presets
oustip presets list              # Lister tous les presets disponibles
oustip presets list --blocklist  # Lister les presets blocklist uniquement
oustip presets list --allowlist  # Lister les presets allowlist uniquement
oustip presets show <nom>        # Afficher les details d'un preset spécifique

# Activer/desactiver
oustip enable                    # Activer le blocage
oustip disable                   # Désactiver le blocage (conserver la config)

# Verification et recherche d'IP
oustip check 1.2.3.4            # Vérifier si une IP est bloquee dans le pare-feu
oustip search 1.2.3.4           # Rechercher une IP dans allow/blocklists
oustip search 1.2.3.4 --dns     # Rechercher avec résolution DNS

# Gestion de la liste blanche
oustip allowlist add 1.2.3.4    # Ajouter une IP a la liste blanche
oustip allowlist del 1.2.3.4    # Supprimer une IP de la liste blanche
oustip allowlist list           # Lister les IPs en liste blanche
oustip allowlist reload         # Recharger depuis la config

# Gestion des blocklists
oustip blocklist list           # Lister toutes les sources de blocklist
oustip blocklist enable <nom>   # Activer une source de blocklist
oustip blocklist disable <nom>  # Désactiver une source de blocklist
oustip blocklist show <nom>     # Afficher les IPs d'une source (20 premieres)
oustip blocklist show <nom> --limit 50  # Afficher avec limite personnalisee
oustip blocklist show <nom> --dns  # Afficher avec résolution DNS

# Gestion des IPs assumees (chevauchements reconnus allow+block)
oustip assume list              # Lister les IPs assumees
oustip assume add 1.2.3.4       # Reconnaitre un chevauchement (plus de notifications)
oustip assume del 1.2.3.4       # Retirer de la liste assumee

# Gestion IPv6
oustip ipv6 status              # Afficher le statut IPv6
oustip ipv6 disable             # Désactiver IPv6 via sysctl
oustip ipv6 enable              # Activer IPv6

# Rapports
oustip report                   # Générer un rapport texte (top 10 IPs bloquees)
oustip report --format json     # Générer un rapport JSON
oustip report --format markdown # Générer un rapport Markdown
oustip report --send            # Envoyer via email/gotify/webhook
oustip report --top 20          # Afficher les 20 IPs les plus bloquees (défaut: 10)

# Surveillance de sante
oustip health                   # Exécuter un controle de sante
oustip health --json            # Sortie en format JSON (pour monitoring)

# Version et nettoyage
oustip version                  # Afficher la version
oustip uninstall                # Tout supprimer

# Options globales
--config <chemin>               # Chemin de config personnalise
--quiet                         # Mode silencieux (pour cron)
--verbose                       # Mode verbeux
--lang <en|fr>                  # Forcer la langue
```

## Configuration

OustIP utilise deux fichiers de configuration :
- `/etc/oustip/config.yaml` - Configuration principale (interfaces, alertes, parametres)
- `/etc/oustip/presets.yaml` - Sources et presets de blocklist/allowlist

Apres modification des fichiers, exécutez la commande appropriee :
- `oustip update config` - Apres modification de config.yaml
- `oustip update presets && oustip update lists` - Apres modification de presets.yaml

### Configuration par Interface (config.yaml)

```yaml
# Langue (en, fr)
language: fr

# Backend pare-feu (auto, iptables, nftables)
backend: auto

# Mode de filtrage
# - raw: avant conntrack (plus performant)
# - conntrack: apres conntrack (permet les reponses aux connexions sortantes)
mode: conntrack

# Intervalle de mise a jour pour le timer systemd (ex: 4h, 6h, 12h, 1d)
update_interval: "4h"

# Configuration par interface
# Utilisez 'oustip interfaces detect' pour auto-detecter les interfaces
interfaces:
  # Interface WAN - exposee a internet, protection blocklist complete
  eth0:
    mode: wan
    blocklist_preset: paranoid    # Bloquer les IPs suspectes d'internet
    allowlist_preset: cdn_common  # Autoriser CDN (Cloudflare, GitHub, Fastly)

  # Interface LAN - reseau interne, surveillance du trafic sortant
  eth1:
    mode: lan
    allowlist_preset: rfc1918     # Autoriser reseaux prives
    outbound_monitor:             # Surveillance pour détection de compromission
      blocklist_preset: recommended
      action: alert               # alert, block, block_and_alert

  # Interfaces de confiance - pas de filtrage (conteneurs, tunnels VPN)
  docker0:
    mode: trusted
  wg0:
    mode: trusted

# Configuration IPv6
ipv6:
  boot_state: unchanged  # disabled, enabled, unchanged

# Destinations d'alertes
alerts:
  gotify:
    enabled: false
    url: "https://gotify.example.com"
    token: ""                    # Peut etre defini directement ici
    token_env: "MY_GOTIFY_TOKEN" # Ou via variable d'environnement
  email:
    enabled: false
    smtp_host: "smtp.example.com"
    smtp_port: 587
    smtp_user: "alerts@example.com"
    smtp_password: ""            # Peut etre defini via OUSTIP_SMTP_PASSWORD
    from: "oustip@example.com"
    to: "admin@example.com"
  webhook:
    enabled: false
    url: ""
    headers: {}
```

### Configuration des Presets (presets.yaml)

```yaml
# Sources de blocklist
blocklist_sources:
  spamhaus_drop:
    url: https://www.spamhaus.org/drop/drop.txt
    description:
      en: "Spamhaus DROP - Hijacked/leased for spam/malware"
      fr: "Spamhaus DROP - Detournees/louees pour spam/malware"
  # ... autres sources

# Presets blocklist avec heritage
blocklist_presets:
  minimal:
    description:
      fr: "Serveurs production - quasi-zero faux positifs"
    sources:
      - spamhaus_drop
      - spamhaus_edrop
      - dshield

  recommended:
    description:
      fr: "Defaut recommande - bon equilibre"
    extends: minimal  # Herite toutes les sources de minimal
    sources:
      - firehol_level1
      - firehol_level2

# Sources d'allowlist (statiques et dynamiques)
allowlist_sources:
  rfc1918:
    static:
      - "10.0.0.0/8"
      - "172.16.0.0/12"
      - "192.168.0.0/16"
    description:
      fr: "Reseaux prives RFC1918"

  cloudflare:
    url: https://www.cloudflare.com/ips-v4
    url_v6: https://www.cloudflare.com/ips-v6
    description:
      fr: "Plages IP Cloudflare CDN"

# Presets d'allowlist
allowlist_presets:
  cdn_common:
    sources:
      - cloudflare
      - github
      - fastly
```

### Modes d'Interface

| Mode | Description | Cas d'Usage |
|------|-------------|-------------|
| `wan` | Protection blocklist complete | Interfaces exposees a internet |
| `lan` | RFC1918 auto-autorise, surveillance sortante | Interfaces reseau interne |
| `trusted` | Pas de filtrage | Tunnels VPN, bridges conteneurs |

Note: `lo` (loopback) est toujours trusted et ne peut pas etre configure.

### Variables d'Environnement pour les Identifiants

Pour une sécurité renforcée, les identifiants peuvent etre fournis via des variables d'environnement :

| Champ Config | Variable Env par Defaut | Champ Variable Env Personnalisee |
|--------------|-------------------------|----------------------------------|
| `gotify.token` | `OUSTIP_GOTIFY_TOKEN` | `gotify.token_env` |
| `email.smtp_password` | `OUSTIP_SMTP_PASSWORD` | `email.smtp_password_env` |

Ordre de priorite :
1. Variable d'environnement personnalisee (si `token_env` ou `smtp_password_env` est defini)
2. Variable d'environnement par défaut (`OUSTIP_GOTIFY_TOKEN` ou `OUSTIP_SMTP_PASSWORD`)
3. Valeur dans le fichier de config

Exemple avec systemd :

```bash
# /etc/systemd/system/oustip.service.d/credentials.conf
[Service]
Environment="OUSTIP_GOTIFY_TOKEN=votre-token-secret"
Environment="OUSTIP_SMTP_PASSWORD=votre-mot-de-passe-smtp"
```

## Presets

| Preset | Listes | Faux Positifs | Cas d'Usage |
|--------|--------|---------------|-------------|
| `minimal` | spamhaus_drop, spamhaus_edrop, dshield | Quasi aucun | Serveurs de production |
| `recommended` | minimal + firehol_level1, firehol_level2 | Tres rares | Choix par défaut |
| `full` | recommended + firehol_level3 | Possibles | Environnements haute sécurité |
| `paranoid` | full + firehol_level4 | Probables | Protection maximale |

## Modes de Filtrage

### Mode Conntrack (par défaut)

Les règles sont appliquees apres le suivi de connexion. Cela permet :
- Les reponses aux connexions sortantes meme si la destination est dans la blocklist
- Les alertes sur les connexions sortantes vers des IPs bloquees (indicateur de compromission possible)

### Mode Raw

Les règles sont appliquees avant le suivi de connexion. C'est :
- Plus performant (pas de surcharge conntrack)
- Bloque TOUT le trafic vers/depuis les IPs en blocklist, y compris les reponses

## Compilation depuis les Sources

```bash
# Prérequis : Rust 1.75+
cargo build --release

# Exécuter les tests
cargo test

# Cross-compilation pour musl (binaire statique)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Stripper le binaire
strip target/x86_64-unknown-linux-musl/release/oustip
```

## Fonctionnement

1. **Fetch** - Télécharge les blocklists depuis les sources configurees (avec limites de taille : 10 Mo par fichier, 50 Mo au total)
2. **Aggregate** - Fusionne les CIDRs chevauchants pour l'efficacité
3. **Filter** - Supprime les IPs en liste blanche (manuelles + fournisseurs CDN)
4. **Apply** - Injecte les règles dans des chaines de pare-feu dediees

OustIP crée des chaines isolees (`OUSTIP-INPUT`, `OUSTIP-FORWARD` pour iptables ou `table ip oustip` pour nftables) et ne touche jamais aux règles existantes.

## Securite

OustIP est conçu avec la sécurité a l'esprit :

- **Validation des Entrees** - Toutes les entrées utilisateur (presets, intervalles, en-tetes) sont validees
- **Prevention des Injections** - Les fichiers d'unite systemd et les en-tetes HTTP sont assainis
- **Protection des Identifiants** - Support des variables d'environnement au lieu du texte clair dans la config
- **Operations Atomiques** - Les fichiers d'etat sont ecrits de maniere atomique pour eviter la corruption
- **Limites de Téléchargement** - Les téléchargements de blocklist sont limites en taille pour prevenir les DoS
- **Pas de Log de Reponse** - Les logs d'erreur n'incluent pas les corps de reponse potentiellement sensibles

## Integration CrowdSec

OustIP est complementaire a CrowdSec. Alors qu'OustIP bloque les IPs malveillantes connues depuis des blocklists publiques, CrowdSec fournit une détection basee sur le comportement.

Pour utiliser les deux :

1. Installer CrowdSec séparément (voir [documentation CrowdSec](https://docs.crowdsec.net/))
2. OustIP et CrowdSec utilisent des chaines de pare-feu séparées et n'interferent pas

## Dépannage

### Aucune regle appliquee

```bash
# Vérifier si OustIP est actif
oustip status

# Vérifier les règles de pare-feu
sudo nft list table ip oustip  # nftables
sudo iptables -L OUSTIP-INPUT  # iptables
```

### Permission refusee

OustIP nécessite les privileges root pour la manipulation du pare-feu :

```bash
sudo oustip update
```

### Échec du téléchargement de blocklist

Vérifier la connectivite reseau et reessayer :

```bash
oustip update --verbose
```

### Le timer systemd ne fonctionne pas

```bash
# Vérifier le statut du timer
systemctl status oustip.timer

# Activer et demarrer le timer
sudo systemctl enable --now oustip.timer

# Consulter les logs
journalctl -u oustip.service
```

## Licence

AGPL-3.0-or-later - voir [LICENSE](LICENSE)

Cela signifie que vous devez partager le code source si vous :
- Distribuez le logiciel
- Fournissez un acces via un reseau (SaaS)

## Environnements Supportes

### Recommande Pour

| Environnement | Notes |
|---------------|-------|
| **Passerelles/Routeurs Linux** | Cas d'usage principal - blocage centralise |
| **Serveurs VPN/Proxy** | Bloquer les IPs malveillantes avant qu'elles n'atteignent les services |
| **Serveurs dedies** | Avec acces root et nftables/iptables |
| **Conteneurs Docker** | Avec `--cap-add NET_ADMIN --network host` |
| **Routeurs domestiques** | OpenWrt, routeurs Linux personnalises |

### Configuration Requise

- **OS**: Linux (kernel 3.13+ pour nftables, 2.4+ pour iptables)
- **Distributions**: Debian, Ubuntu, RHEL/CentOS, Alpine, Arch, etc.
- **Privileges**: Root ou capabilities CAP_NET_ADMIN + CAP_NET_RAW
- **Pare-feu**: nftables (recommande) ou iptables avec ipset
- **Memoire**: ~50 Mo pour 100k IPs, ~512 Mo pour 1M IPs
- **Disque**: ~100 Mo d'espace libre recommande

### Non Recommande Pour

| Environnement | Raison |
|---------------|--------|
| Conteneurs rootless | Necessite CAP_NET_ADMIN |
| Serverless (Lambda, etc.) | Pas d'acces pare-feu natif |
| Load balancers manages | AWS ALB, GCP LB - pas d'acces iptables |
| Windows/macOS | Linux uniquement (nftables/iptables) |

## Avantages et Limites

### Avantages

- **Haute Performance**: Rust + sets nftables = O(1) lookup par paquet
- **Securite Memoire**: Pas de buffer overflows, use-after-free, ou pauses GC
- **Non-Intrusif**: Cree des chaines isolees, ne modifie jamais les règles existantes
- **Agregation Intelligente**: Optimisation CIDR reduit le nombre de règles jusqu'a 70%
- **Détection des Chevauchements**: Détection automatique des conflits allow+block avec résolution DNS
- **Defense en Profondeur**: Validation des entrées, HTTPS obligatoire, zeroisation des credentials
- **Pret pour Production**: Operations atomiques, logique de retry, degradation gracieuse

### Limites

| Limite | Contournement |
|--------|---------------|
| **Pas de détection comportementale** | Utiliser avec CrowdSec pour détection comportementale et ML |
| **Agregation IPv6 limitee** | Considerer `oustip ipv6 disable` si non nécessaire |
| **Pas de rollback automatique** | Utiliser `oustip disable` puis `oustip enable` pour rollback |
| **Blocklists statiques** | Listes mises a jour toutes les 6h par défaut (timer configurable) |

### Comparaison avec Alternatives

| Outil | Objectif | Utiliser Ensemble? |
|-------|----------|-------------------|
| **CrowdSec** | ML + intelligence de menaces communautaire + détection comportementale | Oui - OustIP pour listes statiques, CrowdSec pour dynamique |
| **firewalld** | Gestion pare-feu par zones | Oui - OustIP ajoute des blocklists dynamiques |
| **ufw** | Wrapper pare-feu simple | OustIP prefere pour passerelles |

**Stack Recommandee**: OustIP (blocage preventif) + CrowdSec (reactif/comportemental)

## Architecture IA

OustIP utilise une architecture IA hybride pour l'assistance au developpement. La configuration est centralisée dans `.ai/` et génère des fichiers spécifiques a chaque plateforme.

### Structure

```
.ai/
├── skills/           # Definitions d'agents (source YAML)
├── commands/         # Reference rapide
├── MEMORY.md         # Contexte persistant entre sessions
└── generate.sh       # Generateur multi-plateforme
```

### Plateformes supportees

| Plateforme | Fichiers génères |
|------------|------------------|
| Claude Code | `.claude/agents/*.md` |
| OpenCode | `.opencode/agent/*.md` |
| Ollama | `ollama/Modelfile.*` |
| Continue.dev | `.continuerc.json` |
| Aider | `.aider.conf.yml` |
| Cursor | `.cursorrules` |
| Codex | `.codex/agents/*.md` |

### Utilisation

```bash
# Regénèrer toutes les configs (si VERSION a change)
.ai/generate.sh

# Forcer la regeneration
.ai/generate.sh --force
```

Voir [AGENTS.md](AGENTS.md) pour les règles de developpement et [.ai/MEMORY.md](.ai/MEMORY.md) pour le contexte du projet.

## Contribuer

Les contributions sont les bienvenues ! Merci de :

1. Forker le depot
2. Creer une branche de fonctionnalite
3. Soumettre une pull request

Style de code : `cargo fmt` et `cargo clippy`
