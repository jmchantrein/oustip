# OustIP

[![CI](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml/badge.svg)](https://github.com/jmchantrein/oustip/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

**Gestionnaire de Blocklists IP pour Passerelles Linux**

> *"Oust !"* — Interjection francaise signifiant "Dehors !", "Du balai !"

OustIP est un outil haute performance pour bloquer les IPs malveillantes sur les passerelles et routeurs Linux. Ecrit en Rust pour la securite memoire, zero pause de garbage collection, et une surface d'attaque minimale.

[English Documentation](README.md)

## Fonctionnalites

- **Haute Performance** - Traitement de millions d'IPs avec une latence minimale (auto-detection nftables/iptables)
- **Securite Memoire** - Ecrit en Rust avec des garanties a la compilation
- **Simple** - Installation et configuration en 5 minutes
- **Non-Intrusif** - Ne modifie jamais les regles de pare-feu existantes
- **Flexible** - Supporte nftables (par defaut) et iptables
- **Agregation Intelligente** - Optimisation CIDR pour reduire le nombre de regles
- **Detection des Chevauchements** - Detection automatique des chevauchements allow+block avec resolution DNS
- **Auto-Allowlist** - Liste blanche automatique des fournisseurs CDN (Cloudflare, GitHub, AWS, GCP, Fastly)
- **Alertes** - Notifications via Gotify, email et webhook
- **Bilingue** - Interface en anglais et francais
- **Securise** - Support des variables d'environnement pour les identifiants, validation des entrees, operations atomiques

## Demarrage Rapide

### Installation

```bash
# Telecharger le binaire
curl -sSL https://github.com/jmchantrein/oustip/releases/latest/download/oustip-linux-amd64 \
    -o /usr/local/sbin/oustip
chmod +x /usr/local/sbin/oustip

# Installer (cree la config, le service et le timer systemd)
sudo oustip install

# Modifier la configuration (optionnel)
sudo vim /etc/oustip/config.yaml

# Appliquer les regles
sudo oustip update

# Verifier le statut
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
oustip install                   # Installer OustIP
oustip install --preset paranoid # Installer avec un preset specifique
oustip update                    # Mettre a jour les blocklists et appliquer les regles
oustip update --preset minimal   # Utiliser un preset specifique pour cette execution
oustip update --dry-run          # Simulation: telecharger sans appliquer les regles
oustip stats                     # Afficher les statistiques de blocage
oustip status                    # Afficher le statut actuel

# Activer/desactiver
oustip enable                    # Activer le blocage
oustip disable                   # Desactiver le blocage (conserver la config)

# Verification et recherche d'IP
oustip check 1.2.3.4            # Verifier si une IP est bloquee dans le pare-feu
oustip search 1.2.3.4           # Rechercher une IP dans allow/blocklists
oustip search 1.2.3.4 --dns     # Rechercher avec resolution DNS

# Gestion de la liste blanche
oustip allowlist add 1.2.3.4    # Ajouter une IP a la liste blanche
oustip allowlist del 1.2.3.4    # Supprimer une IP de la liste blanche
oustip allowlist list           # Lister les IPs en liste blanche
oustip allowlist reload         # Recharger depuis la config

# Gestion des blocklists
oustip blocklist list           # Lister toutes les sources de blocklist
oustip blocklist enable <nom>   # Activer une source de blocklist
oustip blocklist disable <nom>  # Desactiver une source de blocklist
oustip blocklist show <nom>     # Afficher les IPs d'une source (20 premieres)
oustip blocklist show <nom> --limit 50  # Afficher avec limite personnalisee
oustip blocklist show <nom> --dns  # Afficher avec resolution DNS

# Gestion des IPs assumees (chevauchements reconnus allow+block)
oustip assume list              # Lister les IPs assumees
oustip assume add 1.2.3.4       # Reconnaitre un chevauchement (plus de notifications)
oustip assume del 1.2.3.4       # Retirer de la liste assumee

# Gestion IPv6
oustip ipv6 status              # Afficher le statut IPv6
oustip ipv6 disable             # Desactiver IPv6 via sysctl
oustip ipv6 enable              # Activer IPv6

# Rapports
oustip report                   # Generer un rapport texte (top 10 IPs bloquees)
oustip report --format json     # Generer un rapport JSON
oustip report --format markdown # Generer un rapport Markdown
oustip report --send            # Envoyer via email/gotify/webhook
oustip report --top 20          # Afficher les 20 IPs les plus bloquees (defaut: 10)

# Surveillance de sante
oustip health                   # Executer un controle de sante
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

Fichier de configuration : `/etc/oustip/config.yaml`

```yaml
# Langue (en, fr)
language: fr

# Backend pare-feu (auto, iptables, nftables)
backend: auto

# Mode de filtrage
# - raw: avant conntrack (plus performant)
# - conntrack: apres conntrack (permet les reponses aux connexions sortantes)
mode: conntrack

# Alerter sur les connexions sortantes vers des IPs bloquees (mode conntrack uniquement)
# Utile pour detecter les compromissions potentielles sur le reseau local
alert_outbound_to_blocklist: true

# Intervalle de mise a jour pour le timer systemd (ex: 6h, 12h, 1d)
update_interval: "6h"

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

# Liste blanche manuelle
allowlist:
  - "192.168.0.0/16"
  - "10.0.0.0/8"
  - "172.16.0.0/12"

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
    smtp_password: ""            # Peut etre defini directement ici
    smtp_password_env: "MY_SMTP_PASS" # Ou via variable d'environnement
    from: "oustip@example.com"
    to: ["admin@example.com"]
  webhook:
    enabled: false
    url: ""
    headers: {}  # En-tetes personnalises optionnels
```

### Variables d'Environnement pour les Identifiants

Pour une securite renforcee, les identifiants peuvent etre fournis via des variables d'environnement :

| Champ Config | Variable Env par Defaut | Champ Variable Env Personnalisee |
|--------------|-------------------------|----------------------------------|
| `gotify.token` | `OUSTIP_GOTIFY_TOKEN` | `gotify.token_env` |
| `email.smtp_password` | `OUSTIP_SMTP_PASSWORD` | `email.smtp_password_env` |

Ordre de priorite :
1. Variable d'environnement personnalisee (si `token_env` ou `smtp_password_env` est defini)
2. Variable d'environnement par defaut (`OUSTIP_GOTIFY_TOKEN` ou `OUSTIP_SMTP_PASSWORD`)
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
| `recommended` | minimal + firehol_level1, firehol_level2 | Tres rares | Choix par defaut |
| `full` | recommended + firehol_level3 | Possibles | Environnements haute securite |
| `paranoid` | full + firehol_level4 | Probables | Protection maximale |

## Modes de Filtrage

### Mode Conntrack (par defaut)

Les regles sont appliquees apres le suivi de connexion. Cela permet :
- Les reponses aux connexions sortantes meme si la destination est dans la blocklist
- Les alertes sur les connexions sortantes vers des IPs bloquees (indicateur de compromission possible)

### Mode Raw

Les regles sont appliquees avant le suivi de connexion. C'est :
- Plus performant (pas de surcharge conntrack)
- Bloque TOUT le trafic vers/depuis les IPs en blocklist, y compris les reponses

## Compilation depuis les Sources

```bash
# Prerequis : Rust 1.75+
cargo build --release

# Executer les tests
cargo test

# Cross-compilation pour musl (binaire statique)
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl

# Stripper le binaire
strip target/x86_64-unknown-linux-musl/release/oustip
```

## Fonctionnement

1. **Fetch** - Telecharge les blocklists depuis les sources configurees (avec limites de taille : 10 Mo par fichier, 50 Mo au total)
2. **Aggregate** - Fusionne les CIDRs chevauchants pour l'efficacite
3. **Filter** - Supprime les IPs en liste blanche (manuelles + fournisseurs CDN)
4. **Apply** - Injecte les regles dans des chaines de pare-feu dediees

OustIP cree des chaines isolees (`OUSTIP-INPUT`, `OUSTIP-FORWARD` pour iptables ou `table ip oustip` pour nftables) et ne touche jamais aux regles existantes.

## Securite

OustIP est concu avec la securite a l'esprit :

- **Validation des Entrees** - Toutes les entrees utilisateur (presets, intervalles, en-tetes) sont validees
- **Prevention des Injections** - Les fichiers d'unite systemd et les en-tetes HTTP sont assainis
- **Protection des Identifiants** - Support des variables d'environnement au lieu du texte clair dans la config
- **Operations Atomiques** - Les fichiers d'etat sont ecrits de maniere atomique pour eviter la corruption
- **Limites de Telechargement** - Les telechargements de blocklist sont limites en taille pour prevenir les DoS
- **Pas de Log de Reponse** - Les logs d'erreur n'incluent pas les corps de reponse potentiellement sensibles

## Integration CrowdSec

OustIP est complementaire a CrowdSec. Alors qu'OustIP bloque les IPs malveillantes connues depuis des blocklists publiques, CrowdSec fournit une detection basee sur le comportement.

Pour utiliser les deux :

1. Installer CrowdSec separement (voir [documentation CrowdSec](https://docs.crowdsec.net/))
2. OustIP et CrowdSec utilisent des chaines de pare-feu separees et n'interferent pas

## Depannage

### Aucune regle appliquee

```bash
# Verifier si OustIP est actif
oustip status

# Verifier les regles de pare-feu
sudo nft list table ip oustip  # nftables
sudo iptables -L OUSTIP-INPUT  # iptables
```

### Permission refusee

OustIP necessite les privileges root pour la manipulation du pare-feu :

```bash
sudo oustip update
```

### Echec du telechargement de blocklist

Verifier la connectivite reseau et reessayer :

```bash
oustip update --verbose
```

### Le timer systemd ne fonctionne pas

```bash
# Verifier le statut du timer
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

## Contribuer

Les contributions sont les bienvenues ! Merci de :

1. Forker le depot
2. Creer une branche de fonctionnalite
3. Soumettre une pull request

Style de code : `cargo fmt` et `cargo clippy`
