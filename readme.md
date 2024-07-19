A simple implementation of Client-Server connection secured with Post Quantum TLS, which makes use of **Ed448-Dilithium3** for PQ X.509 certificates, and **X25519Kyber768** for key exchange mechanism.

## Pre-requisites:
```
Golang (version >= 1.21)
```
Since, the golang's standard `crypto` lib doesn't have proper support for PQC yet (yes, there's a recent X25519Kyber768 merge, but that doesn't include PQ sig schemes), so I decided to make use of [Cloudflare-go](https://github.com/cloudflare/go/), which is essentially Golang's standard library but with some updates to crypto modules which definitely meet our needs: PQ Key share & PQ Sig schemes. 
To install and set this up, run the following commands:
```
$ git clone https://github.com/cloudflare/go /cloudflare-go
$ cd go/src
$ ./make.bash
```
This can now be run using `/cloudflare-go/bin/go`.
For a bit more ease, you may add an alias to this binary executable, for example:
```
alias go2=/cloudflare-go/bin/go/
```

