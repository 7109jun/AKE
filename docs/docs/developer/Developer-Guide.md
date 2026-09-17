# AKE Developer Guide

## 1. Purpose

This document is for developers implementing AKE itself or building software compatible with AKE.

It focuses on:

- AKE internal architecture
- Source tree organization
- Build process
- Runtime architecture
- Package processing
- Security architecture
- Platform APIs
- Testing
- Adding new features

The exact AKE package format is defined by the separate **AKE Specification**.

---

# 2. AKE Architecture

AKE can be viewed as the following layers:

```text
┌─────────────────────────────┐
│            CLI              │
├─────────────────────────────┤
│       Package Manager       │
├─────────────────────────────┤
│          Runtime            │
├─────────────────────────────┤
│   Security / Isolation      │
├─────────────────────────────┤
│       Package Format        │
├─────────────────────────────┤
│      Windows Platform       │
└─────────────────────────────┘
```

Each layer should remain as independent as practical.

---

# 3. Package Processing Pipeline

Package creation:

```text
Source Directory
      ↓
Validation
      ↓
TAR
      ↓
XZ
      ↓
.ake
```

Package use:

```text
.ake
 ↓
XZ decompression
 ↓
TAR parser
 ↓
Package validation
 ↓
Metadata parser
 ↓
Runtime configuration
 ↓
Execution
```

Package contents are untrusted input and must not be assumed to be safe.

Package paths in particular require strict validation.

---

# 4. Source Tree

The source tree can be organized by function:

```text
src/
├── cli/
├── package/
├── archive/
├── metadata/
├── runtime/
├── process/
├── security/
├── repository/
├── volume/
├── network/
├── ipc/
├── service/
├── integration/
├── audit/
└── platform/
    └── windows/
```

The exact file structure may vary.

The important design rule is to keep CLI handling separate from core package and runtime logic.

---

# 5. Language Responsibilities

AKE can combine:

```text
C
C++
Rust
```

A possible division is:

```text
C       → Low-level system and format processing
C++     → Windows integration and higher-level system code
Rust    → Safety-critical or memory-sensitive core modules
```

These are implementation choices rather than package-format requirements.

The implementation language must never change package compatibility.

---

# 6. Building

A Windows development environment generally needs the project's required:

```text
C/C++ compiler
Windows SDK
Rust toolchain
Git
```

A completed build should at minimum support:

```text
ake --help
ake --version
ake verify <package.ake>
```

---

# 7. Development vs. Release Builds

Development builds may retain debug information.

Release builds should verify:

- Correct version information
- Correct target architecture
- Error handling
- Package verification
- Security features
- Logging
- Exit-code forwarding

Release binaries should not contain accidental development-only paths or debug-only options.

---

# 8. Metadata Parser

Metadata uses:

```text
key=value
```

Example:

```text
id=com.example.app
version=1.0.0
entry=bin/app.exe
```

The parser must validate:

```text
Syntax
Keys
Values
Required fields
Allowed values
Duplicate keys
Paths
Versions
```

Fields such as `entry`, `volume.*`, `association.*`, and `protocol.*` require path validation before being mapped to operating-system paths.

---

# 9. Version Comparison

Dependency resolution must use explicit version comparison rules rather than plain string comparison.

Example:

```text
runtime>=2.1.0
```

Meaning:

```text
runtime version >= 2.1.0
```

The following operators must be distinguished:

```text
=
>
>=
<
<=
```

Version parsing and comparison should return deterministic results.

---

# 10. Installation System

The installation system should generally follow:

```text
Package
  ↓
Validation
  ↓
Temporary directory
  ↓
Extraction
  ↓
Metadata validation
  ↓
Commit
  ↓
Database update
```

If an intermediate step fails, temporary state should be removed while preserving the previous valid installation whenever possible.

The same principle applies to updates.

---

# 11. Runtime

The runtime is more than a wrapper around process creation.

Before starting a package process, the runtime should determine at least:

```text
Entry executable
Environment
Working directory
Filesystem policy
Process policy
Network policy
Identity
Resource limits
Volumes
Ports
IPC
Logging
```

It then launches the process through the appropriate Windows APIs and applies the selected policies.

---

# 12. Windows Process Management

Depending on the feature set, Windows-specific code may use:

```text
CreateProcessW
Job Object
Security Token
AppContainer
Named Pipe
WinHTTP
Service Control Manager
Registry APIs
Shell APIs
Windows Cryptography APIs
```

Platform-specific calls should be isolated where practical, for example under:

```text
platform/windows/
```

This keeps the core AKE logic separate from Windows API details.

---

# 13. Job Objects

Windows Job Objects can be used to manage the package process group.

Possible uses include:

- Child-process grouping
- Process-count limits
- Memory limits
- CPU limits
- CPU-time limits
- Group termination

Do not assume that an application consists of only one process.

The runtime must account for child processes when the package permits them.

---

# 14. AppContainer

Stronger Windows isolation can use AppContainer.

Example:

```text
permission.identity=appcontainer
permission.filesystem=appcontainer
```

When AppContainer is used, filesystem permissions and network capabilities must be considered together.

The runtime should provide a translation layer between AKE's abstract policy and the Windows security model.

---

# 15. Networking

The AKE network policy should remain separate from its Windows implementation.

For example:

```text
internet
```

should not be treated as a raw Windows API value.

Instead:

```text
AKE Policy
    ↓
Capability Mapping
    ↓
Windows AppContainer / Network Configuration
```

The implementation and documentation should clearly distinguish AKE-level policy from the exact operating-system capabilities applied.

---

# 16. Volumes

Volumes separate persistent data from the package itself.

Example:

```text
volume.cache.source=@cache
volume.cache.target=data/cache
volume.cache.mode=rw
```

The runtime must validate:

```text
Source
Target
Mode
Duplicate targets
Path traversal
Protected directories
```

Core package areas should not be exposed as arbitrary volume targets:

```text
bin/
config/
lib/
metadata/
```

---

# 17. IPC

Windows Named Pipes can provide AKE IPC.

Example:

```text
\\.\pipe\AKE\<container>\<channel>
```

IPC implementation should consider:

```text
Access control
User SID
Client PID
Container ID
Authentication token
Message size
Framing
Timeouts
Error handling
```

Runtime authentication tokens should remain separate from static package configuration.

---

# 18. Repository

Repository data must be treated as untrusted input.

A typical flow is:

```text
Repository
    ↓
Index
    ↓
Package URL
    ↓
Download
    ↓
SHA-256 verification
    ↓
Signature verification
    ↓
Trust verification
    ↓
Install
```

Each verification stage should remain independently testable.

---

# 19. Digital Signatures

AKE can use a detached signature:

```text
Application.ake
Application.ake.sig
```

Signature verification should cover at least:

```text
Package SHA-256
Public Key
Signature
Trust Store
```

A valid signature and a trusted signing key are separate conditions.

---

# 20. Services

Windows Service integration must be treated separately from ordinary container execution.

A service host must correctly communicate with the Windows Service Control Manager.

When restart policies are used, the SCM's observed failure state must remain consistent with AKE's internal state.

---

# 21. Windows Integration

Registry, Shell, and related integration must be constrained so that an AKE package cannot arbitrarily modify the operating system.

For example, file-association installation should detect conflicts rather than blindly overwriting an existing handler.

---

# 22. Audit Logging

Security-sensitive operations should be written to the audit log when possible.

Examples:

```text
install
update
remove
run
stop
trust
verify
service
policy
```

If user-controlled input is logged, newline and control-character escaping must prevent corruption of the record format.

---

# 23. Error Handling

AKE modules must not convert exceptional conditions into success.

Recommended flow:

```text
Low-level error
      ↓
AKE internal error
      ↓
User-facing error
      ↓
Exit code
```

Separating internal error details from CLI presentation helps maintain consistent behavior.

---

# 24. Testing

AKE should have several categories of tests.

## Package Tests

```text
pack
verify
extract
```

## Installation Tests

```text
install
remove
update
rollback
```

## Runtime Tests

```text
run
detach
stop
logs
```

## Security Tests

```text
path traversal
invalid signature
untrusted key
invalid metadata
```

## Network Tests

```text
deny
internet
private-network
port publishing
```

## IPC Tests

```text
same-container
same-user
public
token authentication
```

## Windows Tests

```text
AppContainer
Job Object
Service
Registry
File Association
URL Protocol
Shortcut
```

---

# 25. Adding New Features

When adding a feature, verify all four layers:

```text
Specification
Runtime
CLI
Tests
```

For example, adding a metadata field should follow:

```text
Metadata specification
        ↓
Metadata parser
        ↓
Runtime behavior
        ↓
CLI / diagnostics
        ↓
Tests
```

A missing layer can cause the implementation and specification to diverge.

---

# 26. Compatibility

Because multiple AKE implementations may exist, internal implementation details must not become accidental compatibility requirements.

The following should remain stable:

```text
Package Format
Metadata
Dependency Rules
Signature Format
Repository Format
Runtime Contract
```

---

# 27. Contributing

When modifying AKE, avoid breaking existing behavior.

A change should include, where applicable:

```text
Changed code
Changed specification
Tests
Documentation
```

If the specification changes, its intended semantics should be made explicit rather than inferred from an implementation.

---

# 28. Commit Guidelines

Keep commits focused on one primary purpose.

Examples:

```text
Add package metadata validation
Fix Windows path traversal check
Add IPC authentication
Update service restart handling
```

Avoid combining unrelated changes into a single commit.

---

# 29. Critical Invariants

The following invariants should always be preserved:

```text
Invalid package
    ↓
Do not execute

Validation failure
    ↓
Do not install

Untrusted package
    ↓
Reject according to policy

Invalid path
    ↓
Reject package access

Installation failure
    ↓
Preserve previous valid state
```

Security-sensitive code should prioritize correctness over convenience.

---

# 30. Developer Checklist

Before submitting a feature, verify:

```text
[ ] Is the specification defined?
[ ] Is input validation present?
[ ] Is error handling present?
[ ] Is Windows-specific behavior isolated?
[ ] Is compatibility preserved?
[ ] Are tests included?
[ ] Is CLI behavior consistent?
[ ] Is documentation updated?
```

---

# 31. Recommended Feature Development Order

Recommended order for a new AKE feature:

```text
Specification
    ↓
Data Model
    ↓
Parser / Validator
    ↓
Core Runtime
    ↓
Platform Integration
    ↓
CLI
    ↓
Tests
    ↓
Documentation
```

This reduces the need to redesign internal behavior after the CLI has already been built.

---

# 32. AKE Development Model

AKE is not just a CLI program.

It is best understood as the combination of:

```text
Package Format
        +
Package Manager
        +
Container Runtime
        +
Security Layer
        +
Windows Integration
```

Changes to one component should therefore be reviewed for effects on the others.

---

# 33. Specification and Implementation

The core principle is:

> **The specification is the interface; the implementation is the realization of that interface.**

An AKE implementation must not make other implementations depend on undocumented internal details.

Conversely, an implementation must not arbitrarily change behavior that is explicitly defined by the specification.

---

# 34. Related Documents

- `AKE Specification`
- `AKE CLI Reference`
- `AKE Security Model`
- `AKE Architecture`
- `AKE Building Guide`
- `AKE Contributing Guide`

These documents should minimize duplicated content and keep their respective purposes clear.

---

# End

**AKE Developer Guide**

This document is for development and maintenance of the AKE implementation.
