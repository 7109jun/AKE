# AKE v1.0.0 Final

AKE is a **Windows-first application package and application-container runtime**.

Package files use the mandatory `.ake` extension. The package payload is a TAR archive compressed with XZ. A normal package contains an executable, configuration, libraries, and metadata.

## Package layout

```text
Example.ake
└── TAR + XZ
    ├── bin/
    │   └── Example.exe
    ├── config/
    ├── lib/
    └── metadata/
        └── package.ake
```

`metadata/package.ake` declares the package identity and runtime policy.

```ini
name=Example
id=com.example.example
version=1.0.0
publisher=AKE Test
architecture=x64
entry=bin/Example.exe
ake_version=1.0
```

## Runtime

```bat
ake run Example.ake
ake run --detach Example.ake
ake ps
ake logs <run-id>
ake stop <run-id>
```

A package can run without installation. Detached runs receive a runtime directory, environment block, log file, and Windows Job Object when supported.

## Package management

```bat
ake pack Example Example.ake
ake verify Example.ake
ake info Example.ake
ake extract Example.ake output
ake install Example.ake
ake update Example.ake
ake remove com.example.example
ake list
ake which com.example.example
```

Installed package state is kept under the AKE database root. Set `AKE_ROOT` to override the root for testing or a custom deployment.

## Repository

```bat
ake repo add main https://example.com/ake
ake repo list
ake repo remove main
ake search example
ake install com.example.example
```

A repository exposes `index.ake-repo`. Package downloads are SHA-256 checked and then fully validated before installation. Repository installs require a trusted signature by default.

## Signatures and trust

AKE v1.0 uses detached ECDSA P-256 / SHA-256 signatures.

```bat
ake keygen publisher.akekey publisher.akepub
ake sign Example.ake publisher.akekey
ake verify-signature Example.ake
ake trust add publisher.akepub Publisher
ake trust list
ake trust verify Example.ake
```

The signature file is normally:

```text
Example.ake.sig
```

The default trust policy is:

```text
local=allow-unsigned
repository=require-trusted
```

## Container isolation

AKE metadata can declare:

```ini
permission.filesystem=package|appcontainer|host
permission.process=children|host
permission.identity=current|restricted|appcontainer
permission.network=host|deny|internet|internet-server|private-network|internet-and-private
```

`appcontainer` requires the matching AppContainer identity. The native Windows layer uses Windows security tokens, AppContainer capabilities, ACLs, and Job Objects where applicable.

## Resource limits

```ini
resource.memory=256MiB
resource.cpu=50%
resource.processes=32
resource.cpu-time=60s
```

Windows Job Objects are used for memory, CPU-rate, process-count, and process-time limits when those limits are declared and supported by the target environment.

## Persistent volumes

```bat
ake volume create demo-cache
ake volume list
ake volume remove demo-cache
```

Metadata:

```ini
volume.cache.source=@demo-cache
volume.cache.target=data/cache
volume.cache.mode=rw
```

Host paths can be declared with an absolute path and `ro`/`rw` mode. Targets are constrained to `data/<path>`.

## IPC and ports

```ini
port.http.protocol=tcp
port.http.container=8080
port.http.host=18080
port.http.publish=loopback

ipc.default.access=same-container
```

Windows Named Pipe endpoints use:

```text
\\.\pipe\AKE\<container-name>\<channel>
```

IPC access policies support `same-user`, `same-container`, and `public`.

## Windows integration

Packages may declare:

- Registry values under the AKE-managed `HKCU\Software\Classes` area.
- File associations.
- URL protocol handlers.
- Start Menu / Desktop shortcuts.

Install, update, and remove operations manage the integration lifecycle.

## Windows services

A package may declare:

```ini
service.name=AKE.ExampleService
service.display-name=Example AKE Service
service.description=Example background service
service.start=auto
service.account=localservice
service.restart=on-failure
service.restart.max-retries=5
service.restart.delay=5s
service.restart.backoff=2
service.restart.reset=24h
```

CLI:

```bat
ake service install com.example.example
ake service start com.example.example
ake service status com.example.example
ake service stop com.example.example
ake service remove com.example.example
```

The service host continues to use the package's runtime identity, filesystem, network, IPC, volume, and resource policies.

## Audit log

```bat
ake audit list
ake audit list --limit 100
ake audit clear
```

The audit file is stored below:

```text
%ProgramData%\AKE\audit\audit.log
```

or below `AKE_ROOT`.

The log records package verification, installation, update, removal, runtime lifecycle, trust decisions, policy denials, service actions, and CLI activity.

The audit file is an operational log, not a tamper-proof security boundary.

## Build

The primary implementation is split across three languages:

```text
Rust
  CLI and runtime orchestration

C
  AKE archive/core parser, TAR/XZ validation, extraction and packaging

C++
  Windows process, security, IPC, volume, service, crypto and Shell/Registry integration
```

### Windows release build

On a Windows development machine with Rust and the required native build environment:

```powershell
.\BUILD-WINDOWS.ps1
```

The default target is `x86_64-pc-windows-msvc`. Override it with `AKE_TARGET`.

### Native regression tests

On a development environment with GCC/G++, liblzma, and the source tree:

```bash
./NATIVE-TESTS.sh
```

The native regression suite covers package validation, extraction, dependencies, network policy, environment setup, runtime ABI, identity, IPC, volumes, and services.

## File limit

The complete AKE v1.0.0 source distribution is intentionally kept below the project limit of **90 files**.

## Final status

```text
AKE version:      1.0.0
Format:           .ake
Archive:          TAR + XZ
Target:           Windows
Languages:        Rust + C + C++
Source file cap:  90
```
