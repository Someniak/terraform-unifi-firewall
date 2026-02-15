# Terraform Provider for UniFi Firewall

A Terraform provider for managing UniFi firewall rules and policies via the UniFi API.

## Prerequisites

- [Go](https://golang.org/doc/install) 1.24 or later
- [Terraform](https://www.terraform.io/downloads.html) 1.0 or later

## Building the Provider

To build the provider binary locally, run:

```bash
make build
```

This will create a `terraform-provider-unifi` binary in the root directory.

## Local Installation

To install the provider locally for development purposes, run:

```bash
make install
```

This command will:
1. Build the provider.
2. Create the necessary directory structure in your local Terraform plugins directory (`~/.terraform.d/plugins/...`).
3. Move the binary to that directory, making it available for Terraform to use.

## Using the Provider

After installation, you can use the provider in your Terraform configurations. See the [examples/](examples/) directory for sample configurations.

### Basic Configuration

```hcl
terraform {
  required_providers {
    unifi = {
      source  = "someniak/unifi"
      version = "0.0.1"
    }
  }
}

provider "unifi" {
  host     = "https://10.0.10.1/proxy/network/integration"
  api_key  = "YOUR_API_KEY"
  site_id  = "auto"
  insecure = true
}
```

## Development

### Cleaning Up

To remove build artifacts and local Terraform state from examples, run:

```bash
make clean
```

### Initializing Examples

To re-initialize the examples with the locally installed provider:

```bash
make test-init
```

### Running a Plan

To run a Terraform plan for the examples:

```bash
make test-plan
```
