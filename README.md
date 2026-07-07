# NimScope v0.1

NimScope est un framework d'audit et de reconnaissance rapide, léger et entièrement asynchrone, conçu pour évaluer la sécurité des environnements Active Directory et des infrastructures Cloud (AWS). Développé en Nim, il utilise une architecture modulaire pilotée par des templates JSON, permettant d'exécuter des vérifications simultanées sans la lourdeur de threads système dédiés.

### Bannière

```bash
█   █ ███ █   █  ████  ███   ███  ████  █████   
██  █░ █░░██ ██░█ ░░░░█ ░░░ █ ░░█ █░░░█ █░░░░░  
█░█ █░░█░░█░█ █░░███░░█░ ░░░█░ ░█░████░░████░░░ 
█░░██░░█░░█░░░█░░ ░░█ █░░   █░░ █░█░░░░ █░░░░   
█░░ █░███░█░░ █░████░░ ███   ███ ░█░░░░░█████░  
 ░░  ░░░░░ ░░  ░░░░░░ ░ ░░░   ░░░ ░░░    ░░░░░  
  ░   ░ ░░░ ░   ░ ░░░   ░░░   ░░░  ░     ░░░░░
```

## Fonctionnalités

- **Moteur Asynchrone :** Basé sur `std/asyncdispatch` pour une gestion optimale des I/O réseau en parallèle.
- **Audit Active Directory :** - Test de *Null Session* LDAP.
  - Vérification de l'obligation de signature SMB (*SMB Signing*).
  - Reconnaissance native de la version de l'OS via l'API Windows (`netapi32`).
- **Audit Cloud :** Évaluation asynchrone de l'exposition des ressources Cloud (ex: ACLs de buckets AWS S3).
- **Extensible :** Ajout de signatures et de tests via de simples fichiers de configuration JSON.

---

## Structure du Projet

```text
NimScope/
├── config/
│   └── ad_defaults.json        # Configuration globale des ports et requêtes AD
├── src/
│   ├── core/
│   │   ├── config_loader.nim   # Chargeur de la configuration JSON globale
│   │   ├── executor.nim        # Moteur d'exécution asynchrone des templates
│   │   ├── loader.nim          # Parseur de templates JSON
│   │   └── logger.nim          # Formatage des sorties (Success, Fail, Info)
│   ├── protocols/
│   │   ├── ldap.nim            # Logique de communication LDAP (WinAPI)
│   │   └── smb.nim             # Paquets bruts SMB et appels NetServerGetInfo
│   └── nimscope.nim            # Point d'entrée principal (CLI avec Cligen)
└── templates/
    ├── active_directory/       # Fichiers JSON de signatures AD
    │   ├── ldap_null_session.json
    │   └── smb_signing_disabled.json
    └── cloud/                  # Fichiers JSON de signatures Cloud
        └── aws_public_s3.json
```        

## Installation

### Prérequis

* Nim (version 2.2.0 ou supérieure)

* OpenSSL (nécessaire pour les requêtes HTTPS du module Cloud)

### Compilation multi-OS

Le projet utilise des appels natifs à l'API Windows (``winim``) pour certaines fonctionnalités de reconnaissance AD avancées. La compilation complète des modules AD est donc optimisée pour Windows.

#### 1. Windows (Environnement natif)

Assure-toi d'avoir OpenSSL installé (ou les DLLs correspondantes dans ton PATH) pour le support HTTPS :

```powershell
nim c -d:release -d:ssl src/nimscope.nim
```

Le binaire généré se trouvera dans ``src/nimscope.exe``.

#### 2. Linux (Debian/Ubuntu)

Note : Les fonctionnalités spécifiques à la WinAPI (comme la récupération de l'OS via SMB) seront limitées ou nécessiteront des adaptations.

```bash
sudo apt install nim openssl libssl-dev

nim c -d:release -d:ssl src/nimscope.nim
```

#### 3. macOS

```bash
brew install nim openssl

nim c -d:release -d:ssl src/nimscope.nim
```

## Utilisation

NimScope expose une interface en ligne de commande (CLI) auto-documentée grâce à ``cligen``.

### Mode Active Directory

- Lance tous les templates AD configurés contre une cible :

```powershell
.\nimscope ad --target "192.168.1.10"
```

- Lancer un template spécifique via son ID :

```powershell
.\nimscope ad --target "192.168.1.10" --template_id "smb-signing-disabled"
```

### Mode Cloud

Vérifier l'existence et l'exposition d'un bucket S3 :

```powershell
.\nimscope cloud --target "mon-bucket-cible"
```

### Options globales disponibles

*    `--template_id` : Spécifie un ID de template précis à exécuter au lieu de tous les lancer (`all` par défaut).

*    ``--silent``      : Masque la bannière ASCII au démarrage.

*    ``--help``        : Affiche l'aide et les arguments de la sous-commande.


## Configuration des Templates (Exemple)

Un template est un simple fichier JSON stocké dans ``templates/``. Exemple pour ``aws_public_s3.json`` :

```json
{
  "id": "aws-public-s3",
  "protocol": "http",
  "port": 443,
  "action": "check-acl",
  "info": {
    "name": "AWS Public S3 Bucket",
    "description": "Vérifie si le bucket S3 est configuré en accès public ou listable.",
    "severity": "HIGH"
  }
}
```
