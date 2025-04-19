# mPVAS-Go

A Go implementation of **mPVAS**, a publicly verifiable, privacy-preserving data aggregation protocol that tolerates **arbitrary collusion** without relying on trusted third parties, and supports **constant-time verification**.

## ✨ Features

- 📦 Privacy-preserving data aggregation
- ✅ Public verifiability (constant time)
- 🔐 Tolerates collusion between users and aggregator
- 🚫 No trusted setup or third party required
- ➕ Includes three extensions:
  - **mPVAS+**: communication-optimized
  - **mPVAS-IV**: malicious user identification
  - **mPVAS-UD**: fault-tolerant under user dropout

## 📦 Structure
```
.
├── cmd/         # Entry points for nodes and aggregator
├── internal/
│   ├── p2p/     # libp2p-based messaging
│   ├── crypto/  # cryptographic primitives
│   └── protocol/# mPVAS core logic
```


## 🚀 Run

```bash
go run cmd/node/main.go 10000
```

You can launch multiple nodes and simulate aggregation and verification.

## 📖 Reference

This project is based on the paper:

> "mPVAS: Publicly Verifiable Privacy-Preserving Data Aggregation Without Trusted Third Parties"

---

MIT License
```
