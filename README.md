# pvtr-terraform

Terraform for pvtr plugins

## Prerequisites

### just

[just](https://github.com/casey/just) is a command runner used for local development tasks.

Install with Homebrew:

```sh
brew install just
```

## Usage

### Linting

Validate all Terraform modules:

```sh
just lint
```

This runs `terraform init -backend=false` and `terraform validate` against each module in `modules/`.
