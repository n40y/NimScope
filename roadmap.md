# ROADMAP EN 5 PHASES
Phase 0 : Fondations (1-2 jours)
Objectif : Rendre le code propre et maintenable.
À faire :

Créer src/core/types.nim (tous les types communs)
Créer src/core/reporter.nim (JSON + console propre)
Améliorer config_loader.nim
Mettre à jour executor.nim pour utiliser les nouveaux types
Organiser les imports correctement
Ajouter --output json et --verbose

*Priorité : Très haute*

## Phase 1 : Amélioration Protocoles AD (1 semaine)
AD - Priorités :

### LDAP (déjà bon)
Ajouter des recherches avancées (users, groups, SPNs, descriptions contenant des mots de passe)

### SMB
Remplacer le packet hardcodé par un SMB Packet Builder
Ajouter énumération des shares

Kerberos (nouveau fichier)
Détection AS-REP Roasting
Détection comptes avec SPN (Kerberoasting)
Vérification délégation unconstrained

### NTLM / Auth
Support basique username/password

Fichiers à créer/modifier :

src/protocols/ad/ (ou garder dans protocols/ pour l’instant)
kerberos.nim
enumeration.nim
smb.nim (version améliorée)


## Phase 2 : Cloud (4-5 jours)

Améliorer le module HTTP Cloud
Ajouter :
AWS S3 (list + permissions)
AWS IMDSv1 / IMDSv2
AWS IAM (via API)
Azure (Entra ID, Storage, Key Vault)
GCP (optionnel plus tard)

Ajouter support de credentials (Access Key, etc.)


## Phase 3 : Moteur & UX (1 semaine)

Support liste de cibles (--targets targets.txt)
Mode asynchrone avec limite de concurrence (--threads 50)
Stealth : random delays, jitter, user-agent rotation
Barre de progression + statistiques en temps réel
Logging dans fichier
Interface CLI plus jolie (cligen + terminal ou colored)


## Phase 4 : Professionnalisation & Polish (1-2 semaines)

Templates avancés avec extractors (récupérer users, hashes, ACLs…)
Rapport HTML beau (avec Tailwind ou simple CSS)
Scoring de risque global
Mode "quiet" / "silent" / "loot"
Documentation complète (--help riche)
Compilation multi-plateforme (Windows + Linux)


## Phase 5 : Advanced (optionnel – futur)

Support authentification complète (Kerberos ticket, NTLM relay)
Intégration BloodHound (export JSON)
Modules d’attaque légers (password spraying, etc.)
Plugin system
Version GUI (optionnel avec Nim + Webview)
