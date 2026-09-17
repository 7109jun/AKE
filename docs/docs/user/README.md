# AKE
## Application Package & Container

AKE is a Windows-first application package and container system.

It allows a Windows application to be distributed and executed as a single `.ake` package while the AKE runtime handles installation, execution, dependencies, security policies, resource limits, and lifecycle management.

An AKE package can contain:

```text
bin/
config/
lib/
data/
metadata/
```

---

# Why AKE?

Traditional Windows applications may distribute executables, DLLs, configuration files, additional runtimes, and data across multiple locations.

AKE provides a single package unit:

```text
MyApplication.ake
```

The package can contain the application and the metadata needed by the AKE runtime to manage it.

---

# Running an Installed Package

Run an installed package by package ID:

```text
ake run com.example.hello
```

Or run a package file directly:

```text
ake run Hello.ake
```

---

# Installing a Package

```text
ake install Hello.ake
```

List installed packages:

```text
ake list
```

Find an installation location:

```text
ake which com.example.hello
```

Remove a package:

```text
ake remove com.example.hello
```

---

# Running in the Background

```text
ake run --detach com.example.hello
```

List running containers:

```text
ake ps
```

List all containers:

```text
ake ps --all
```

Stop a container:

```text
ake stop <run-id>
```

---

# Viewing Logs

```text
ake logs <run-id>
```

View only the most recent lines:

```text
ake logs <run-id> --tail 100
```

---

# Creating a Package

Assume the project has the following structure:

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

Create the package:

```text
ake pack hello Hello.ake
```

Verify it:

```text
ake verify Hello.ake
```

Then install it:

```text
ake install Hello.ake
```

---

# Security

AKE provides features including:

- Package structure validation
- SHA-256 integrity verification
- Digital signatures
- Trust Store
- Filesystem policies
- Process isolation
- Network policies
- Windows AppContainer
- Resource limits
- Audit logging

Sign a package:

```text
ake sign Hello.ake
```

Verify its signature:

```text
ake verify-signature Hello.ake
```

---

# Repositories

Add a repository:

```text
ake repo add example https://example.com/ake/
```

Search for a package:

```text
ake search hello
```

Install by package ID:

```text
ake install com.example.hello
```

Repository metadata and package hashes can be validated before installation.

---

# Volumes

Create a persistent volume:

```text
ake volume create app-data
```

List volumes:

```text
ake volume list
```

Remove a volume:

```text
ake volume remove app-data
```

---

# Windows Integration

AKE packages can integrate with Windows through features such as:

- File associations
- Custom URL protocols
- Shortcuts
- User-scoped Registry registration
- Windows Services

---

# Windows Services

Register an application as a Windows Service:

```text
ake service install com.example.server
ake service start com.example.server
ake service status com.example.server
```

Stop it:

```text
ake service stop com.example.server
```

---

# AKE vs. Generic Archive Files

An `.ake` file is not just a `.tar.xz` archive.

```text
.ake
 ├── Package Format
 ├── Metadata
 ├── Dependency Management
 ├── Runtime
 ├── Container Isolation
 ├── Resource Limits
 ├── Networking
 ├── IPC
 ├── Volumes
 ├── Security
 └── Windows Integration
```

The AKE runtime interprets these package-level rules.

---

# Documentation

For the exact package and metadata rules, see the **AKE v1.0 Specification**.

Developers working on the AKE implementation should use the **AKE Developer Guide** and related development documents.

---

# Document Version

This documentation targets **AKE v1.0**.
