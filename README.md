# AKE

## Application Package & Container

AKE is a **Windows-first application package and container system** designed to distribute and execute Windows applications as a single `.ake` package.

It manages an application's executables, configuration, libraries, data, dependencies, runtime policies, and security policies as a single package unit. The AKE runtime can install, execute, update, and remove these packages.

> **One package. One runtime.**

---

## Features

- `.ake` package format
- TAR + XZ-based package storage
- Application metadata
- Dependency management
- Package installation / update / removal
- Package repositories
- SHA-256 integrity verification
- Digital signatures
- Trust Store
- Filesystem isolation policies
- Process isolation
- Windows AppContainer
- CPU / memory / process-count / CPU-time limits
- Persistent volumes
- Port publishing
- Named Pipe-based IPC
- Container state and log management
- Windows Registry integration
- File extension associations
- URL protocol registration
- Windows shortcuts
- Windows Services
- Audit logging

---

## AKE Package

A basic AKE package has the following structure:

```text
MyApp.ake
└── TAR + XZ
    ├── bin/
    │   └── MyApp.exe
    ├── config/
    ├── lib/
    ├── data/
    └── metadata/
        └── package.ake
```

### Metadata Example

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

---

## Quick Start

### Create a Package

```text
ake pack ./hello Hello.ake
```

### Verify a Package

```text
ake verify Hello.ake
```

### Install

```text
ake install Hello.ake
```

### Run

```text
ake run com.example.hello
```

### Run in the Background

```text
ake run --detach com.example.hello
```

### List Running Containers

```text
ake ps
```

### View Logs

```text
ake logs <run-id>
```

### Stop a Container

```text
ake stop <run-id>
```

---

## Security

AKE provides not only package-level integrity verification, but also runtime security policies.

```text
Package Validation
        ↓
SHA-256 Integrity
        ↓
Digital Signature
        ↓
Trust Store
        ↓
Runtime Isolation
        ↓
Resource Limits
```

Not every AKE execution mode provides the same security boundary. In particular, `permission.filesystem=package` and Windows AppContainer represent different levels of isolation.

---

## Project Structure

```text
AKE/
├── src/
│   ├── cli/
│   ├── package/
│   ├── archive/
│   ├── metadata/
│   ├── runtime/
│   ├── process/
│   ├── security/
│   ├── repository/
│   ├── volume/
│   ├── network/
│   ├── ipc/
│   ├── service/
│   ├── integration/
│   ├── audit/
│   └── platform/
│       └── windows/
│
├── docs/
│   ├── specification/
│   ├── user/
│   └── developer/
│
└── README.md
```

The AKE implementation can combine **C, C++, and Rust**. Internal implementation details are kept separate from the package specification.

---

## Documentation

### User

[User Guide](docs/user/README.md)

Explains the basic usage of AKE, including installation, package creation, execution, logs, volumes, and repositories.

### Developer

[Developer Guide](docs/developer/Developer-Guide.md)

Explains AKE architecture, source code, building, runtime, security, testing, and feature development.

### Specification

[AKE v1.0 Specification](docs/specification/AKE-Specification.md)

Defines the `.ake` package structure, metadata, runtime, dependencies, security, and Windows integration rules.

---

## Main CLI Commands

| Command | Description |
|---|---|
| `ake pack` | Create an AKE package |
| `ake verify` | Verify a package |
| `ake extract` | Extract a package |
| `ake install` | Install a package |
| `ake run` | Run a package |
| `ake update` | Update a package |
| `ake remove` | Remove a package |
| `ake list` | List installed packages |
| `ake search` | Search repositories |
| `ake repo` | Manage repositories |
| `ake sign` | Sign a package |
| `ake trust` | Manage the Trust Store |
| `ake ps` | Show container state |
| `ake logs` | Show container logs |
| `ake stop` | Stop a container |
| `ake volume` | Manage volumes |
| `ake ports` | Show port information |
| `ake ipc` | Manage IPC |
| `ake integration` | Manage Windows integration |
| `ake service` | Manage Windows Services |
| `ake audit` | Manage audit logs |

---

## AKE vs. Generic Archive Files

AKE is not simply a `.tar.xz` file.

```text
Generic Archive
    └── Files + Compression

AKE
    ├── Package Format
    ├── Metadata
    ├── Dependencies
    ├── Package Management
    ├── Runtime
    ├── Container Isolation
    ├── Security
    ├── Volumes
    ├── Networking
    ├── IPC
    └── Windows Integration
```

AKE is therefore a **system that defines both an application package format and its execution environment**.

---

## Version

Current specification version:

```text
AKE v1.0.0
```

The version format is:

```text
MAJOR.MINOR.PATCH
```

For detailed compatibility rules, see the [AKE Specification](docs/specification/AKE-Specification.md).

---

## License

The license for this repository is defined by the `LICENSE` file in the project root.

---

## AKE

**Application Package & Container**

```text
.ake
    =
Application Package
    +
Container Runtime
```
