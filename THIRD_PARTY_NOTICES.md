# Third-party notices

| Field | Value |
|---|---|
| Repository | `digital.vasic.security` |
| Revision | measured 2026-11-24 against the `go.mod` files named below |
| Referenced by | `LICENSE` section 4 |
| Gate | `scripts/verify_licence.sh` requires this file |

`LICENSE` section 4 states that third-party components remain under their own licences,
listed in this file. This file lists them. It does not grant, change or restrict any right
under those licences.

## Scope and method

- **Nothing is vendored.** This repository contains no copied third-party source tree
  (`vendor/`, `third_party/`, `node_modules/`) and no git submodules. Third-party Go modules
  are resolved at build time from `go.mod` / `go.sum`. Every file in the repository that
  carries a copyright line names the repository owner.
- **Source of the list:** the `require` blocks of the `go.mod` named below, direct and
  indirect. Own-organisation modules (`digital.vasic.*`) are not third-party and are listed
  separately.
- **How each licence was determined:** the module at the pinned version was downloaded with
  `go mod download` and its licence file read; the licence name was assigned from the licence
  text. A row says UNKNOWN where no licence file could be read.
- **Not covered:** the Go standard library and toolchain (distributed under the Go
  project's BSD-3-Clause licence, not copied into this repository) and tools a developer may
  install separately.

## Go modules required by `go.mod`

| Module | Version | Relation | Licence | Licence file |
|---|---|---|---|---|
| `github.com/stretchr/testify` | `v1.11.1` | direct | MIT | LICENSE |
| `golang.org/x/crypto` | `v0.52.0` | direct | BSD-3-Clause | LICENSE |
| `github.com/davecgh/go-spew` | `v1.1.2-0.20180830191138-d8f796af33cc` | indirect | ISC | LICENSE |
| `github.com/kr/pretty` | `v0.3.1` | indirect | MIT | License (read manually) |
| `github.com/pmezard/go-difflib` | `v1.0.1-0.20181226105442-5d4384ee4fb2` | indirect | BSD-3-Clause | LICENSE |
| `github.com/rogpeppe/go-internal` | `v1.14.1` | indirect | BSD-3-Clause | LICENSE |
| `golang.org/x/sys` | `v0.45.0` | indirect | BSD-3-Clause | LICENSE |
| `gopkg.in/check.v1` | `v1.0.0-20201130134442-10cb98267c6c` | indirect | BSD-2-Clause | LICENSE |
| `gopkg.in/yaml.v3` | `v3.0.1` | indirect | MIT AND Apache-2.0 (MIT covers the files ported from libyaml; Apache-2.0 the rest) | LICENSE +NOTICE |

## Items that could not be verified

None of the modules above is UNKNOWN. Licence names were assigned from licence text
and not from legal review; consult each module's own licence file for the binding terms.
