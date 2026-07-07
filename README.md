# NimScope v0.1

NimScope is a fast, lightweight, and fully asynchronous audit and reconnaissance framework designed to assess the security of Active Directory environments and Cloud infrastructures (AWS). Developed in Nim, it utilizes a modular architecture driven by JSON templates, allowing concurrent checks to run without the overhead of dedicated system threads.

### Banner

```bash
█   █ ███ █   █  ████  ███   ███  ████  █████   
██  █░ █░░██ ██░█ ░░░░█ ░░░ █ ░░█ █░░░█ █░░░░░  
█░█ █░░█░░█░█ █░░███░░█░ ░░░█░ ░█░████░░████░░░ 
█░░██░░█░░█░░░█░░ ░░█ █░░   █░░ █░█░░░░ █░░░░   
█░░ █░███░█░░ █░████░░ ███   ███ ░█░░░░░█████░  
 ░░  ░░░░░ ░░  ░░░░░░ ░ ░░░   ░░░ ░░░    ░░░░░  
  ░   ░ ░░░ ░   ░ ░░░   ░░░   ░░░  ░     ░░░░░
```

## Features

- *Asynchronous Engine*: Powered by ``std/asyncdispatch`` for optimal concurrent handling of network I/O.

- *Active Directory Audit*: - LDAP Null Session testing.

  - SMB Signing requirement validation.

  - Native OS version discovery via the Windows API (``netapi32``).

- *Cloud Audit*: Asynchronous evaluation of Cloud resource exposure (e.g., AWS S3 bucket ACLs).

- *Extensible*: Easily add new signatures and tests via simple JSON configuration files.

---

## Project Structure

```text
NimScope/
├── config/
│   └── ad_defaults.json        # Global configuration for AD ports and queries
├── src/
│   ├── core/
│   │   ├── config_loader.nim   # Global JSON configuration loader
│   │   ├── executor.nim        # Asynchronous template execution engine
│   │   ├── loader.nim          # JSON template parser
│   │   └── logger.nim          # Output formatting (Success, Fail, Info)
│   ├── protocols/
│   │   ├── ldap.nim            # LDAP communication logic (WinAPI)
│   │   └── smb.nim             # Raw SMB packets and NetServerGetInfo calls
│   └── nimscope.nim            # Main entrypoint (CLI via Cligen)
└── templates/
    ├── active_directory/       # AD JSON signature files
    │   ├── ldap_null_session.json
    │   └── smb_signing.json
    └── cloud/                  # Cloud JSON signature files
        └── aws_imds_leak.json
        └── aws_public_s3.json
```        

## Installation

### Prerequisites

- Nim (version 2.2.0 or higher)

- OpenSSL (required for HTTPS requests in the Cloud module)


### Cross-OS Compilation

The project relies on native Windows API calls (``winim``) for advanced AD reconnaissance features. Full compilation of AD modules is therefore optimized for Windows.

#### 1. Windows (Native Environment)

Ensure OpenSSL is installed (or corresponding DLLs are in your PATH) for HTTPS support:

```powershell
nim c -d:release -d:ssl src/nimscope.nim
```

The generated binary will be located at ``src/nimscope.exe``.


#### 2. Linux (Debian/Ubuntu)

Note: Specific WinAPI features (like OS retrieval via SMB) will be limited or require adaptations.

```bash
sudo apt install nim openssl libssl-dev

nim c -d:release -d:ssl src/nimscope.nim
```

#### 3. macOS

```bash
brew install nim openssl

nim c -d:release -d:ssl src/nimscope.nim
```


## Usage

NimScope exposes a self-documenting Command Line Interface (CLI) thanks to ``cligen``.

### Active Directory Mode

* Run all configured AD templates against a target:

```powershell
.\nimscope ad --target "192.168.1.10"
```

* Run a specific template via its ID:

```powershell
.\nimscope ad --target "192.168.1.10" --template_id "smb-signing-disabled"
```

### Cloud Mode

Check the existence and exposure of an S3 bucket:

```powershell
.\nimscope cloud --target "mon-bucket-cible"
```

### Available Global Options

* ``--template_id`` : Specifies a precise template ID to execute instead of running all of them (``all`` by default).

* ``--silent``      : Hides the ASCII banner on startup.

* ``--help``        : Displays help and arguments for the subcommand.


## Template Configuration (Example)

A template is a simple JSON file stored in ``templates/``. 
Examples :

---
### 1. ``templates/cloud/aws_public_s3.json``
```json
{
  "id": "aws-public-s3",
  "protocol": "http",
  "port": 443,
  "action": "check-acl",
  "info": {
    "name": "AWS Public S3 Bucket",
    "description": "Checks if the S3 bucket is configured with public or listable access.",
    "severity": "HIGH"
  }
}
```

---
### 2. `templates/active_directory/ldap_null_session.json`
```json
{
  "id": "ldap-null-session",
  "info": {
    "name": "Active Directory Null Session LDAP",
    "description": "Checks if the domain controller allows anonymous enumeration via LDAP.",
    "severity": "HIGH",
    "author": "n40y"
  },
  "protocol": "ldap",
  "action": "anonymous-bind",
  "port": 389,
  "matchers": {
    "status": "SUCCESS"
  }
}
```

---
### 3. `templates/active_directory/smb-signing.json`
```json
{
  "id": "smb-signing-disabled",
  "info": {
    "name": "SMB Signing Not Required",
    "description": "Checks if SMB packet signing is required on the target to prevent relay attacks.",
    "severity": "MEDIUM",
    "author": "n40y"
  },
  "protocol": "smb",
  "action": "check-signing",
  "port": 445
}
```

