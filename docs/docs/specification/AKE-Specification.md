# AKE v1.0
## Application Package & Container Specification

**Document Language:** English  
**Specification Version:** 1.0.0  
**Document Status:** Official Specification  
**Target Platform:** Windows  
**File Extension:** `.ake`

---

# 1. Overview

## 1.1 What is AKE?

AKE is an **Application Package & Container** system.

AKE provides a way to distribute applications as a single package and provides a runtime for installing, validating, executing, and managing those packages.

An AKE package can manage the following as a single unit:

- Executable files
- Configuration files
- Libraries
- Application data
- Package metadata
- Dependency information
- Permission and security policies
- Resource limits
- Volume configuration
- Network configuration
- IPC configuration
- Windows integration settings
- Service settings

AKE is not intended to be only a compression format.

The AKE runtime can install, validate, execute, and, when required, provide an isolated process environment similar to a container.

---

# 2. Core Concepts

AKE is built around the following concepts.

## 2.1 Package

A package is an AKE file using the `.ake` extension.

An AKE package uses a TAR archive compressed with XZ.

The conceptual structure is:

```text
application.ake
    │
    └── XZ
         │
         └── TAR
              ├── bin/
              ├── config/
              ├── lib/
              ├── data/
              └── metadata/
```

---

## 2.2 Container

A container is a runtime unit used to execute an AKE package.

The following features can be applied during execution:

- Process group management
- Filesystem policy
- Network policy
- Windows security token policy
- Resource limits
- Volume attachment
- Port publishing
- IPC endpoints
- Runtime state management
- stdout/stderr logging

---

## 2.3 Package ID

Each package has a unique ID.

Example:

```text
com.example.hello
```

The package ID is used to identify an installed package.

---

## 2.4 Version

Each package has a version.

Example:

```text
1.0.0
```

Versions are used for dependency resolution and updates.

---

# 3. `.ake` File Format

## 3.1 Extension

An AKE package must use the `.ake` extension.

Example:

```text
MyApp.ake
```

The following names are not treated as AKE packages:

```text
MyApp.tar
MyApp.tar.xz
MyApp.zip
```

Even if their internal contents are equivalent to TAR + XZ, the `.ake` extension is mandatory for AKE package identification.

---

## 3.2 Physical Format

The base AKE package data format is:

```text
Filesystem
    ↓
TAR
    ↓
XZ
    ↓
.ake
```

An AKE implementation must decompress XZ and then interpret the TAR archive.

---

## 3.3 Package Root

Paths inside a package are resolved relative to the package root.

Valid examples:

```text
bin/app.exe
config/app.conf
lib/example.dll
data/cache.dat
metadata/package.ake
```

Invalid examples:

```text
../file
../../file
C:\file
/absolute/path
```

Package paths must not allow path traversal outside the package root.

---

# 4. Package Directory Structure

A standard AKE package uses the following structure:

```text
package/
├── bin/
├── config/
├── lib/
├── data/
└── metadata/
    └── package.ake
```

## 4.1 `bin/`

Stores executable files.

Example:

```text
bin/MyApp.exe
```

The default executable is specified by the `entry` metadata field.

---

## 4.2 `config/`

Stores application configuration files.

Examples:

```text
config/application.ini
config/settings.json
```

---

## 4.3 `lib/`

Stores package-local libraries.

Examples:

```text
lib/example.dll
lib/runtime.dll
```

The AKE runtime may provide the package-local library path through environment variables.

---

## 4.4 `data/`

Stores application and runtime data.

Examples:

```text
data/cache/
data/database/
data/assets/
```

---

## 4.5 `metadata/`

Stores AKE package metadata.

Required file:

```text
metadata/package.ake
```

---

# 5. Package Metadata

## 5.1 Basic Format

Metadata is UTF-8 encoded text using the `key=value` format.

Example:

```text
id=com.example.hello
version=1.0.0
name=Hello
architecture=x64
entry=bin/hello.exe
```

---

## 5.2 Basic Fields

### `id`

The unique identifier of the package.

Format:

```text
id=<package-id>
```

Example:

```text
id=com.example.hello
```

---

### `version`

The package version.

Format:

```text
version=<version>
```

Example:

```text
version=1.0.0
```

---

### `name`

A human-readable package name.

Example:

```text
name=Hello Application
```

---

### `architecture`

The CPU architecture targeted by the package.

Example:

```text
architecture=x64
```

---

### `entry`

The path to the program to execute, relative to the package root.

Example:

```text
entry=bin/hello.exe
```

The path must be a relative path within the package.

---

# 6. Dependencies

A package can declare dependencies on other packages.

Format:

```text
dependency=<package-id><operator><version>
```

Examples:

```text
dependency=runtime>=2.1.0
dependency=tools=3.0.0
```

Supported operators:

| Operator | Meaning |
|---|---|
| `=` | Exactly the specified version |
| `>` | Greater than the specified version |
| `>=` | Greater than or equal to the specified version |
| `<` | Less than the specified version |
| `<=` | Less than or equal to the specified version |

AKE checks:

- Whether the dependency exists
- Whether the version condition is satisfied
- Self-dependencies
- Cyclic dependencies

If dependency requirements are not satisfied, the operation must fail.

---

# 7. Environment Variables

The AKE runtime can provide environment variables related to the package runtime.

Standard variables:

```text
AKE_PACKAGE_ROOT
AKE_PACKAGE_LIB
AKE_PACKAGE_CONFIG
AKE_PACKAGE_DATA
```

Each variable identifies the corresponding path for the current package.

---

## 7.1 User-defined Package Environment Variables

The following format can be used:

```text
env.NAME=value
```

Examples:

```text
env.APP_MODE=production
env.API_MODE=v1
```

AKE provides these variables to the package process at runtime.

The host process environment itself must not be permanently modified.

---

# 8. Runtime

## 8.1 Executing a Package

A package can be executed with:

```text
ake run MyApp.ake
```

An installed package can be executed by package ID:

```text
ake run com.example.hello
```

---

## 8.2 Execution Sequence

A typical runtime flow is:

```text
Identify package
    ↓
Validate package
    ↓
Read metadata
    ↓
Resolve dependencies
    ↓
Determine runtime policy
    ↓
Configure execution environment
    ↓
Create process
    ↓
Wait for process termination
    ↓
Return exit code
```

---

## 8.3 Exit Code

For foreground execution, AKE returns the exit code of the entry process.

Example:

```text
MyApp.exe → exit code 0
AKE       → exit code 0
```

---

# 9. Installation

An AKE package can be installed with:

```text
ake install MyApp.ake
```

A typical installation sequence is:

```text
Validation
 ↓
Create temporary installation area
 ↓
Place package
 ↓
Validate metadata
 ↓
Register package in package database
 ↓
Commit to final installation area
```

An installation failure must not leave an incomplete package in the normal installed state.

---

# 10. Installed Packages

Installed packages are managed by package ID.

List installed packages:

```text
ake list
```

Find the installation location:

```text
ake which com.example.hello
```

Remove a package:

```text
ake remove com.example.hello
```

---

# 11. Updates

A package can be updated to a newer version.

```text
ake update MyApp.ake
```

An update should prepare the new package before replacing the installed version.

If an update fails, the previous version should remain available whenever practical.

---

# 12. Repositories

AKE can use package repositories.

Add a repository:

```text
ake repo add <name> <url>
```

List repositories:

```text
ake repo list
```

Remove a repository:

```text
ake repo remove <name>
```

Search for packages:

```text
ake search <query>
```

Install by package ID:

```text
ake install com.example.hello
```

---

## 12.1 Repository Index

The default repository index file is:

```text
index.ake-repo
```

The index can provide:

- Package ID
- Version
- Architecture
- Name
- Download URL
- SHA-256 hash

---

## 12.2 Package Integrity Verification

Downloaded packages must be compared against the repository-provided SHA-256 hash.

A package with a mismatched hash must not be installed.

---

# 13. Digital Signatures

AKE supports detached digital signatures for packages.

Signature file:

```text
MyApp.ake.sig
```

The signature is stored separately from the package itself.

This allows the package content to remain unchanged while a detached signature authenticates it.

---

## 13.1 Signature Target

AKE calculates a SHA-256 digest of the package and signs that digest.

Conceptually:

```text
MyApp.ake
   ↓
SHA-256
   ↓
Package Digest
   ↓
Digital Signature
```

---

## 13.2 Key Generation

```text
ake keygen
```

---

## 13.3 Signing

```text
ake sign MyApp.ake
```

---

## 13.4 Signature Verification

```text
ake verify-signature MyApp.ake
```

A Windows implementation may use the Windows cryptography APIs available on the target system.

---

# 14. Trust Store

AKE can manage trusted public keys through a Trust Store.

Add a key:

```text
ake trust add <key>
```

Remove a key:

```text
ake trust remove <key-id>
```

List keys:

```text
ake trust list
```

Verify a package:

```text
ake trust verify MyApp.ake
```

Show policy:

```text
ake trust policy
```

---

## 14.1 Signature Policy

The default policy can distinguish local packages from repository packages.

Example defaults:

```text
local=allow-unsigned
repository=require-trusted
```

A signature file that exists but fails verification must not be silently treated as an unsigned package.

---

# 15. Filesystem Isolation

AKE can define a filesystem policy for package execution.

```text
permission.filesystem=package
```

Supported modes:

```text
package
appcontainer
host
```

---

## 15.1 `package`

Apply package-local filesystem access policy around the package runtime environment.

This mode is an AKE runtime policy and must not be interpreted as a complete kernel-level security boundary.

---

## 15.2 `appcontainer`

Use Windows AppContainer-based isolation.

```text
permission.filesystem=appcontainer
```

AppContainer can be used when a stronger Windows security boundary is required.

---

## 15.3 `host`

Use host filesystem access policy.

```text
permission.filesystem=host
```

This mode may conflict with stronger isolation policies where necessary.

---

# 16. Process Isolation

The process policy can be specified as:

```text
permission.process=children
```

or:

```text
permission.process=host
```

In `children` mode, AKE can manage a package and its child processes as a single process group.

Windows Job Objects can be used to group related processes.

---

# 17. Network Isolation

Network policy can be specified as:

```text
permission.network=host
permission.network=deny
permission.network=internet
permission.network=internet-server
permission.network=private-network
permission.network=internet-and-private
```

### `host`

Use host network policy.

### `deny`

Deny network access.

### `internet`

Allow Internet client access.

### `internet-server`

Support Internet server behavior.

### `private-network`

Allow private network access.

### `internet-and-private`

Allow both Internet and private-network access.

Windows AppContainer execution can map these policies to the corresponding network capabilities.

---

# 18. Resource Limits

AKE can apply runtime resource limits to containers.

Example:

```text
resource.memory=256MiB
resource.cpu=50%
resource.processes=32
resource.cpu-time=60s
```

Supported limit categories include:

- Memory
- CPU usage
- Process count
- CPU time

A Windows implementation can use Job Objects for these controls.

---

## 18.1 Memory

Example:

```text
resource.memory=256MiB
```

Sets a memory limit for the container process group.

---

## 18.2 CPU

Example:

```text
resource.cpu=50%
```

Specifies a CPU usage limit.

---

## 18.3 Process Count

Example:

```text
resource.processes=32
```

Limits the number of active processes that can be created.

---

## 18.4 CPU Time

Example:

```text
resource.cpu-time=60s
```

Limits cumulative CPU time.

---

# 19. Container State

AKE manages the runtime state of containers.

Run in the background:

```text
ake run --detach MyApp.ake
```

List running containers:

```text
ake ps
```

List all containers including terminated ones:

```text
ake ps --all
```

Stop a container:

```text
ake stop <run-id>
```

---

# 20. Logs

AKE can store stdout/stderr logs for executed containers.

View logs:

```text
ake logs <run-id>
```

View the last 100 lines:

```text
ake logs <run-id> --tail 100
```

Logs and runtime state can be maintained in AKE's persistent runtime data area.

---

# 21. Volumes

AKE supports persistent volumes.

Create a volume:

```text
ake volume create <name>
```

List volumes:

```text
ake volume list
```

Remove a volume:

```text
ake volume remove <name>
```

Metadata example:

```text
volume.cache.source=@demo-cache
volume.cache.target=data/cache
volume.cache.mode=rw
```

A host directory may also be used as the source:

```text
volume.cache.source=C:\Data\Cache
volume.cache.target=data/cache
volume.cache.mode=ro
```

---

## 21.1 Volume Targets

Volume targets are generally placed below `data/`.

Examples:

```text
data/cache
data/database
```

Core package areas must not be used as volume targets:

```text
bin/
config/
lib/
metadata/
```

Path traversal must also be rejected.

---

# 22. Ports

AKE can map a container port to a host port.

Example:

```text
port.http.protocol=tcp
port.http.container=8080
port.http.host=18080
port.http.publish=loopback
```

Show port information:

```text
ake ports
```

---

## 22.1 Publishing Scope

At minimum, a local-only publishing scope can be represented as:

```text
loopback
```

A `loopback` port is intended to be accessible from the local computer.

---

# 23. IPC

AKE can provide IPC using Windows Named Pipes.

Show an IPC name:

```text
ake ipc name <run-id> <channel>
```

Start an IPC server:

```text
ake ipc serve <run-id> <channel>
```

Call an IPC endpoint:

```text
ake ipc call <run-id> <channel>
```

---

## 23.1 Endpoint

The Windows Named Pipe endpoint has the following general form:

```text
\\.\pipe\AKE\<container-name>\<channel>
```

---

## 23.2 Message Format

IPC data can be transferred using length-prefixed message framing.

The runtime limits message size. The baseline implementation uses a maximum of 1 MiB.

---

# 24. IPC Access Control

The default IPC access policy can be specified as:

```text
ipc.default.access=same-container
```

Supported policies:

```text
same-container
same-user
public
```

### `same-container`

Only the same container may access the endpoint.

### `same-user`

Access by the same Windows user is allowed.

### `public`

Public access is allowed.

---

## 24.1 Authentication Token

A per-container runtime token can be used for stronger IPC authentication.

Generate a token:

```text
ake ipc token
```

Secure IPC server:

```text
ake ipc secure-serve ...
```

Secure IPC call:

```text
ake ipc secure-call ...
```

Runtime authentication tokens must not be stored as plaintext static secrets in package metadata.

---

# 25. Execution Identity

AKE can restrict the Windows security identity used by the package process.

```text
permission.identity=current
permission.identity=restricted
permission.identity=appcontainer
```

---

## 25.1 `current`

Use the current user's security token.

---

## 25.2 `restricted`

Use a restricted Windows token.

A typical implementation can reduce token privileges using mechanisms such as disabling maximum privileges.

---

## 25.3 `appcontainer`

Use a Windows AppContainer identity.

AppContainer identity can be combined with filesystem and network policies.

---

# 26. Windows Integration

AKE can integrate applications with Windows.

Supported categories include:

- Registry
- File associations
- URL protocols
- Shortcuts

Commands:

```text
ake integration install <package-id>
ake integration status <package-id>
ake integration remove <package-id>
```

---

# 27. Registry Integration

A package can register data in a restricted portion of the Windows Registry.

Example:

```text
registry.base.key=Software\Classes\Example.App
registry.base.value=...
registry.base.data=...
```

The default integration policy targets user-scoped areas and does not modify HKLM by default.

---

# 28. File Associations

A file extension can be associated with an application.

Example:

```text
association.foo.extension=.foo
association.foo.progid=Example.Foo
association.foo.description=Example File
association.foo.command=bin/example.exe "%1"
```

File association installation must not blindly overwrite an existing system handler.

---

# 29. URL Protocols

A custom URL protocol can be registered.

Example:

```text
protocol.example.scheme=example
protocol.example.description=Example Protocol
protocol.example.command=bin/example.exe "%1"
```

---

# 30. Shortcuts

An AKE package can define a Windows Shell shortcut.

Example:

```text
shortcut.main.name=Example Application
shortcut.main.target=bin/example.exe
shortcut.main.location=Desktop
```

A Windows implementation can use the Shell APIs to create the shortcut.

---

# 31. Windows Services

An AKE package can be registered as a Windows Service.

Example:

```text
service.name=ExampleService
service.display-name=Example Service
service.description=Example background service
service.start=auto
service.account=localservice
```

Supported start modes:

```text
auto
manual
disabled
```

Supported accounts:

```text
localservice
networkservice
localsystem
```

---

## 31.1 Service Commands

Install:

```text
ake service install <package-id>
```

Start:

```text
ake service start <package-id>
```

Status:

```text
ake service status <package-id>
```

Stop:

```text
ake service stop <package-id>
```

Remove:

```text
ake service remove <package-id>
```

Service host:

```text
ake service host <package-id>
```

---

# 32. Service Restart Policy

A service failure policy can be configured.

Example:

```text
service.restart=on-failure
service.restart.max-retries=5
service.restart.delay=10s
service.restart.backoff=2x
service.restart.reset=300s
```

Supported policies:

```text
never
on-failure
always
```

The Windows Service Control Manager can be used to implement the restart behavior.

An abnormal exit must remain visible to the Service Control Manager rather than being hidden by reporting a normal STOPPED state first.

---

# 33. Audit Logging

AKE can record security and system operations in an audit log.

Default location:

```text
%ProgramData%\AKE\audit\audit.log
```

Example event categories:

```text
verify
pack
extract
install
update
remove
run
stop
trust
policy
service
cli
```

---

## 33.1 Audit Log Format

The log can use fields such as:

```text
AKE-AUDIT 1
timestamp=...
event=...
name=...
result=...
pid=...
package_id=...
package_version=...
details=...
```

Special characters must be escaped so that newlines and other delimiters do not corrupt the log format.

---

## 33.2 Audit Log Failure

A normal AKE operation is not required to fail solely because an audit record could not be written.

Security-sensitive environments may define a separate policy requiring successful audit logging.

---

# 34. Audit Log Commands

List audit records:

```text
ake audit list
```

List up to 100 records:

```text
ake audit list --limit 100
```

Clear the audit log:

```text
ake audit clear
```

---

# 35. Package Validation

AKE packages should be structurally validated before installation or execution whenever applicable.

Validation can include:

- `.ake` extension
- XZ format
- TAR format
- Allowed paths
- Duplicate paths
- Special files
- Symbolic links
- Required metadata
- Entry point
- Metadata validity
- File integrity

---

# 36. Extraction

An AKE package can be extracted to another directory.

```text
ake extract MyApp.ake output/
```

Extraction must validate:

- Path traversal
- Absolute paths
- Duplicate files
- Unauthorized special files
- Symbolic-link or reparse-point abuse
- Maximum entry count
- Maximum decompressed data size

If extraction would conflict with existing destination files, the implementation should fail safely.

---

# 37. Integrity and Trust

AKE distinguishes the following concepts:

```text
Integrity
Authentication
Trust
```

## Integrity

A cryptographic hash such as SHA-256 is used to determine whether package contents have changed.

## Authentication

A digital signature verifies that a particular key signed the package digest.

## Trust

The Trust Store determines whether that public key is trusted by policy.

These states are therefore different:

```text
Hash valid
Signature valid
Key trusted
```

and:

```text
Hash valid
Signature valid
Key not trusted
```

The second case can still be rejected by the trust policy.

---

# 38. Unsafe Package Paths

The following package paths must not be allowed:

```text
../test
../../test
/Windows/System32/test
C:\Windows\System32\test
\\server\share\test
```

Package paths must remain inside the package's logical root.

---

# 39. Package Storage

Installed packages are managed in the AKE system storage area.

A Windows installation can use a root such as:

```text
%ProgramData%\AKE
```

For example:

```text
%ProgramData%\AKE\
├── packages/
├── db/
├── runtime/
├── security/
└── audit/
```

The exact subdirectory layout may vary by implementation, but installed package identity and version must be managed consistently.

---

# 40. Runtime State

Each container execution can have a unique runtime ID.

Example:

```text
run-01JEXAMPLE
```

The runtime ID can be used with:

```text
ake ps
ake logs <run-id>
ake stop <run-id>
ake ports
ake ipc ...
```

---

# 41. Foreground and Detached Execution

## Foreground

```text
ake run MyApp.ake
```

AKE waits for process termination and returns the process exit code.

## Detached

```text
ake run --detach MyApp.ake
```

The container can continue running after the AKE CLI exits.

A detached container is stopped explicitly:

```text
ake stop <run-id>
```

---

# 42. Core CLI Commands

| Command | Function |
|---|---|
| `pack` | Create a package |
| `verify` | Verify a package |
| `extract` | Extract a package |
| `run` | Run a package |
| `install` | Install a package |
| `remove` | Remove a package |
| `list` | List installed packages |
| `which` | Show installation location |
| `update` | Update a package |
| `search` | Search repository packages |
| `repo` | Manage repositories |
| `keygen` | Generate signing keys |
| `sign` | Sign a package |
| `verify-signature` | Verify a package signature |
| `trust` | Manage the Trust Store |
| `ps` | Show container state |
| `logs` | Show container logs |
| `stop` | Stop a container |
| `volume` | Manage volumes |
| `ports` | Show port information |
| `ipc` | Manage IPC |
| `integration` | Manage Windows integration |
| `service` | Manage Windows Services |
| `audit` | Manage audit logs |

---

# 43. Package Creation Example

Assume the following project:

```text
hello/
├── bin/
│   └── hello.exe
├── config/
├── lib/
├── data/
└── metadata/
    └── package.ake
```

`metadata/package.ake`:

```text
id=com.example.hello
version=1.0.0
name=Hello Application
architecture=x64
entry=bin/hello.exe

permission.filesystem=package
permission.process=children
permission.network=deny
permission.identity=appcontainer

resource.memory=256MiB
resource.cpu=50%
resource.processes=32
resource.cpu-time=60s
```

Create the package:

```text
ake pack hello Hello.ake
```

Verify it:

```text
ake verify Hello.ake
```

Install it:

```text
ake install Hello.ake
```

Run it:

```text
ake run com.example.hello
```

---

# 44. Minimal Package

A minimal conceptual AKE package is:

```text
package/
├── bin/
│   └── application.exe
└── metadata/
    └── package.ake
```

Metadata:

```text
id=com.example.application
version=1.0.0
architecture=x64
entry=bin/application.exe
```

`config`, `lib`, and `data` may be omitted when the application does not need them.

---

# 45. Security Principles

AKE implementations should follow these principles.

## 45.1 Default Deny

Access that is not required should not be enabled by default.

## 45.2 Input Validation

Package paths, metadata, repository data, and command-line input must be validated.

## 45.3 Least Privilege

Only required permissions should be granted.

## 45.4 Separate Trust from Signatures

A valid signature and a trusted signing key are not the same concept.

## 45.5 Fail Safely

A failed validation or installation step must not leave a corrupted package in the normal installed state.

---

# 46. Runtime Security Boundary

Not every AKE execution mode provides the same strength of security boundary.

For example:

```text
permission.filesystem=package
```

is an AKE runtime-level filesystem policy.

In contrast:

```text
permission.identity=appcontainer
```

combined with Windows AppContainer can provide a stronger operating-system-level security boundary.

Therefore, documentation and implementations must not generally describe every mode as a complete sandbox.

---

# 47. Windows-First Design

AKE is designed with Windows as its primary target.

The following features are particularly integrated with Windows:

- AppContainer
- Windows Job Object
- Windows Security Token
- Windows Named Pipe
- Windows Service Control Manager
- Windows Registry
- Windows Shell
- Windows WinHTTP
- Windows Cryptography APIs

The AKE package format itself uses TAR + XZ, but major runtime integration features are defined around Windows.

---

# 48. Implementation Languages

An AKE implementation may combine:

```text
C
C++
Rust
```

The responsibilities of each language are implementation-specific.

The language choice must not change AKE package compatibility.

Different AKE implementations written in different languages should still be able to process the same compliant `.ake` package.

---

# 49. Compatibility Principles

An AKE v1.0 implementation should process the following consistently:

- `.ake` extension
- TAR + XZ package structure
- `metadata/package.ake`
- Core metadata
- Dependency syntax
- Path validation
- Version comparison
- Signature format
- Trust Store policy
- Core runtime environment variables

Internal storage or module organization may differ between implementations.

---

# 50. Versioning

AKE specification versions use:

```text
MAJOR.MINOR.PATCH
```

Example:

```text
1.0.0
```

## MAJOR

Indicates incompatible specification changes.

## MINOR

Indicates backward-compatible feature additions.

## PATCH

Indicates bug fixes or documentation changes that do not fundamentally change the meaning of the specification.

---

# 51. Specification Change Policy

Before changing the AKE specification, consider whether existing packages can still be processed.

New features should be designed so that an older implementation that does not understand a feature can fail safely when required.

Compatibility requires special care around:

- Metadata
- Package structure
- Signatures
- Trust Store
- Runtime policies
- Repository indexes

---

# 52. Error Handling

An AKE implementation must not report success when an operation has failed.

Examples:

```text
Corrupted package
→ Error

Signature mismatch
→ Error

Untrusted signing key
→ Reject according to policy

Missing dependency
→ Installation or execution failure

Invalid path
→ Reject package

Resource limit exceeded
→ Terminate according to runtime policy
```

Error messages should provide a useful human-readable explanation whenever practical.

---

# 53. Package Lifecycle

A typical AKE package lifecycle is:

```text
Development
 ↓
Package creation
 ↓
Validation
 ↓
Signing
 ↓
Publication or distribution
 ↓
Installation
 ↓
Execution
 ↓
Log / state management
 ↓
Update
 ↓
Removal
```

---

# 54. AKE Compared with Generic Archive Files

An `.ake` file is not merely a generic TAR + XZ archive.

Generic TAR + XZ:

```text
Files
+
Compression
```

AKE:

```text
Package Format
+
Metadata
+
Dependencies
+
Installation System
+
Execution System
+
Container Runtime
+
Security Policies
+
Signatures
+
Trust Store
+
Volumes
+
Networking
+
IPC
+
Windows Integration
```

Therefore, an AKE file is an application package interpreted by an AKE runtime.

---

# 55. Full Example

Example package metadata:

```text
id=com.example.webapp
version=2.0.0
name=Example Web Application
architecture=x64
entry=bin/web.exe

dependency=runtime>=2.1.0

permission.filesystem=appcontainer
permission.process=children
permission.network=internet
permission.identity=appcontainer

resource.memory=512MiB
resource.cpu=75%
resource.processes=64
resource.cpu-time=300s

env.APP_ENV=production

volume.cache.source=@web-cache
volume.cache.target=data/cache
volume.cache.mode=rw

port.http.protocol=tcp
port.http.container=8080
port.http.host=18080
port.http.publish=loopback

ipc.default.access=same-container

service.name=ExampleWeb
service.display-name=Example Web
service.description=Example Web Service
service.start=auto
service.account=localservice
service.restart=on-failure
service.restart.max-retries=5
service.restart.delay=10s
```

---

# 56. Full Execution Example

Create package:

```text
ake pack ./webapp WebApp.ake
```

Verify:

```text
ake verify WebApp.ake
```

Sign:

```text
ake sign WebApp.ake
```

Install:

```text
ake install WebApp.ake
```

Run:

```text
ake run com.example.webapp
```

Detached:

```text
ake run --detach com.example.webapp
```

Inspect containers:

```text
ake ps
```

View logs:

```text
ake logs <run-id>
```

View ports:

```text
ake ports
```

Stop:

```text
ake stop <run-id>
```

Update:

```text
ake update WebApp-New.ake
```

Remove:

```text
ake remove com.example.webapp
```

---

# 57. AKE v1.0 Concept Summary

```text
.ake package
├── TAR + XZ
├── metadata/package.ake
├── executable
├── configuration
├── libraries
└── data

Runtime
├── process execution
├── isolation
├── identity
├── network
├── resources
├── volumes
├── ports
├── IPC
└── logs

Distribution
├── install
├── update
├── remove
├── repository
└── dependency resolution

Security
├── SHA-256
├── digital signature
├── Trust Store
├── filesystem policy
├── process policy
├── AppContainer
└── audit log

Windows Integration
├── Registry
├── File Association
├── URL Protocol
├── Shortcut
└── Windows Service
```

---

# 58. Purpose of the Specification

The purpose of AKE is to integrate Windows application distribution into a single managed unit.

```text
Application
+
Dependencies
+
Configuration
+
Runtime Policy
+
Security Policy
+
Container Runtime
=
AKE Package
```

AKE defines a system that manages packaging, distribution, installation, execution, isolation, and lifecycle operations as a single package-oriented system.

---

# 59. Documentation Authority

This document defines the English-language AKE v1.0 specification.

If a Korean version is published, the Korean and English versions should remain semantically equivalent for:

- Specification definitions
- Metadata
- Commands
- Security policies
- Error conditions
- Package structure
- Version compatibility

Terminology in translated documentation must not change the technical meaning of the specification.

---

# 60. End

**AKE v1.0**

> Application Package & Container

```text
.ake
    =
Application Package
    +
Container Runtime
```
