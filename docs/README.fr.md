# OustIP

**Gestionnaire de Blocklists IP pour Passerelles Linux**

OustIP est un outil haute performance pour bloquer les IPs malveillantes sur les passerelles et routeurs Linux. Écrit en Rust pour la sécurité mémoire, zéro pause de garbage collection et une surface d'attaque minimale.

## Fonctionnalités

- **Haute Performance** - Traitement de millions d'IPs avec latence minimale
- **Sécurité Mémoire** - Écrit en Rust avec garanties à la compilation
- **Simple** - Installation et configuration en 5 minutes
- **Non-Intrusif** - Ne modifie jamais les règles firewall existantes
- **Flexible** - Support iptables et nftables
- **Agrégation Intelligente** - Optimisation CIDR pour réduire le nombre de règles
- **Auto-Allowlist** - Whitelist automatique des CDN (Cloudflare, GitHub, etc.)
- **Alertes** - Notifications Gotify, email et webhook
- **Bilingue** - Interface anglais et français

## Démarrage Rapide

### Installation

```bash
# Télécharger le binaire
curl -sSL https://github.com/jmchantrein/oustip/releases/latest/download/oustip-linux-amd64 \
    -o /usr/local/bin/oustip
chmod +x /usr/local/bin/oustip

# Installer (crée config, service systemd, timer)
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
docker pull ghcr.io/jmchantrein/oustip:latest
docker run --rm --cap-add NET_ADMIN --network host oustip update
```

## Utilisation

```bash
# Commandes principales
oustip install                   # Installer OustIP
oustip install --preset paranoid # Installer avec un preset spécifique
oustip update                    # Mettre à jour les blocklists et appliquer
oustip update --preset minimal   # Utiliser un preset spécifique
oustip stats                     # Afficher les statistiques de blocage
oustip status                    # Afficher le statut actuel

# Activation/désactivation
oustip enable                    # Activer le blocage
oustip disable                   # Désactiver le blocage (garde la config)

# Vérification d'IP
oustip check 1.2.3.4            # Vérifier si une IP est bloquée

# Gestion de l'allowlist
oustip allowlist add 1.2.3.4    # Ajouter une IP à l'allowlist
oustip allowlist del 1.2.3.4    # Retirer une IP de l'allowlist
oustip allowlist list           # Lister les IPs dans l'allowlist
oustip allowlist reload         # Recharger depuis la config

# Gestion IPv6
oustip ipv6 status              # Afficher le statut IPv6
oustip ipv6 disable             # Désactiver IPv6 via sysctl
oustip ipv6 enable              # Activer IPv6

# Désinstallation
oustip uninstall                # Tout supprimer

# Options globales
--config <chemin>               # Chemin de config personnalisé
--quiet                         # Mode silencieux (pour cron)
--verbose                       # Mode verbeux
--lang <en|fr>                  # Forcer la langue
```

## Configuration

Fichier de configuration : `/etc/oustip/config.yaml`

```yaml
# Langue (en, fr)
language: fr

# Backend firewall (auto, iptables, nftables)
backend: auto

# Mode de filtrage
# - raw : avant conntrack (plus performant)
# - conntrack : après conntrack (permet les réponses aux connexions sortantes)
mode: conntrack

# Preset (minimal, recommended, full, paranoid)
preset: recommended

# Sources de blocklists
blocklists:
  - name: firehol_level1
    url: https://iplists.firehol.org/files/firehol_level1.netset
    enabled: true
  # ... autres listes

# Auto-allowlist des fournisseurs CDN
auto_allowlist:
  cloudflare: true
  github: true
  google_cloud: false
  aws: false
  fastly: false

# Allowlist manuelle
allowlist:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "172.16.0.0/12"

# Destinations des alertes
alerts:
  gotify:
    enabled: false
    url: "https://gotify.example.com"
    token: ""
  email:
    enabled: false
    # ...
  webhook:
    enabled: false
    url: ""
```

## Presets

| Preset | Listes | Faux Positifs |
|--------|--------|---------------|
| `minimal` | spamhaus_drop, spamhaus_edrop, dshield | Quasi aucun |
| `recommended` | minimal + firehol_level1, firehol_level2 | Très rares |
| `full` | recommended + firehol_level3 | Possibles |
| `paranoid` | full + firehol_level4 | Probables |

## Modes de Filtrage

### Mode Conntrack (défaut)

Les règles sont appliquées après le suivi de connexion. Cela permet :
- Les réponses aux connexions sortantes même si la destination est dans la blocklist
- Les alertes sur les connexions sortantes vers des IPs bloquées (indicateur de compromission)

### Mode Raw

Les règles sont appliquées avant le suivi de connexion. C'est :
- Plus performant (pas d'overhead conntrack)
- Bloque TOUT le trafic vers/depuis les IPs bloquées, y compris les réponses

## Compilation depuis les Sources

```bash
# Prérequis : Rust 1.75+
cargo build --release

# Cross-compilation pour musl (binaire statique)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Réduire le binaire
strip target/x86_64-unknown-linux-musl/release/oustip
```

## Fonctionnement

1. **Récupération** - Télécharge les blocklists depuis les sources configurées
2. **Agrégation** - Fusionne les CIDRs qui se chevauchent pour l'efficacité
3. **Filtrage** - Retire les IPs en allowlist (manuelles + fournisseurs CDN)
4. **Application** - Injecte les règles dans des chaînes firewall dédiées

OustIP crée des chaînes isolées (`OUSTIP-INPUT`, `OUSTIP-FORWARD` pour iptables ou `table ip oustip` pour nftables) et ne touche jamais aux règles existantes.

## Intégration CrowdSec

OustIP est complémentaire à CrowdSec. Tandis qu'OustIP bloque les IPs connues comme malveillantes depuis des blocklists publiques, CrowdSec fournit une détection basée sur le comportement.

Pour utiliser les deux :

1. Installer CrowdSec séparément (voir [documentation CrowdSec](https://docs.crowdsec.net/))
2. OustIP et CrowdSec utilisent des chaînes firewall séparées et n'interfèrent pas

## Dépannage

### Aucune règle appliquée

```bash
# Vérifier si OustIP est actif
oustip status

# Vérifier les règles firewall
sudo nft list table ip oustip  # nftables
sudo iptables -L OUSTIP-INPUT  # iptables
```

### Permission refusée

OustIP nécessite les privilèges root pour manipuler le firewall :

```bash
sudo oustip update
```

### Échec de téléchargement des blocklists

Vérifier la connectivité réseau et réessayer :

```bash
oustip update --verbose
```

## Licence

Licence MIT - voir [LICENSE](../LICENSE)

## Contribution

Les contributions sont les bienvenues ! Merci de :

1. Forker le dépôt
2. Créer une branche feature
3. Soumettre une pull request

Style de code : `cargo fmt` et `cargo clippy`
