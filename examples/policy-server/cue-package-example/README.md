# CUE Package Configuration Example

This example demonstrates using CUE packages with imports to organize complex policy configurations.

## Benefits of Using CUE Packages

- **Imports**: Split configuration across multiple files
- **Reusable definitions**: Define common patterns once, reuse everywhere
- **Type safety**: CUE validates structure and types
- **Constraints**: Define validation rules inline with configuration

## Example Structure

```
cue-package-example/
├── policy.cue          # Main policy configuration
├── users.cue           # User definitions
└── hosts.cue           # Host-specific policies
```

## How to Use

Load the entire directory as a package:

```bash
epithet policy --config-file ./cue-package-example --ca-pubkey "..." --port 9999
```

## Files

### policy.cue

Main configuration that imports other files:

```cue
package policy

// CA and OIDC configuration
ca_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAbCdE..."
oidc: "https://accounts.google.com"

// Import user and host definitions
users: #Users
hosts: #Hosts

// Default policies
defaults: {
    allow: {
        root: ["admin"]
        ubuntu: ["dev", "ops"]
    }
    expiration: "5m"
    extensions: {
        "permit-pty": ""
        "permit-agent-forwarding": ""
    }
}
```

### users.cue

User definitions with reusable schemas:

```cue
package policy

// Define user schema for validation
#User: {
    tags: [...string]
}

// User definitions
#Users: {
    "alice@example.com": ["admin", "dev"]
    "bob@example.com": ["dev"]
    "charlie@example.com": ["ops"]
}
```

### hosts.cue

Host-specific policies with shared patterns:

```cue
package policy

// Define host policy schema
#HostPolicy: {
    allow: [string]: [...string]
    expiration?: string
    extensions?: [string]: string
}

// Host definitions
#Hosts: {
    "prod-db-01": #HostPolicy & {
        allow: {
            postgres: ["admin"]
        }
        expiration: "2m"
    }
    
    "dev-server": #HostPolicy & {
        allow: {
            testuser: ["dev"]
        }
        expiration: "10m"
    }
}
```

## Advanced Features

### Validation Constraints

Add constraints to ensure configuration correctness:

```cue
package policy

// Ensure all expiration values are valid durations
defaults: {
    expiration: =~"^[0-9]+(s|m|h)$"
}

// Ensure all tags are lowercase
#Users: [string]: [...=~"^[a-z]+$"]
```

### Shared Definitions

Define reusable patterns:

```cue
package policy

// Common production host policy
#ProductionHost: #HostPolicy & {
    expiration: "2m"
    allow: {
        deploy: ["ops"]
    }
}

#Hosts: {
    "prod-web-01": #ProductionHost
    "prod-web-02": #ProductionHost
    "prod-api-01": #ProductionHost & {
        allow: {
            deploy: ["ops", "api-team"]
        }
    }
}
```

### Computed Values

Use CUE's computation features:

```cue
package policy

// Define environment-based expiration
#Environment: "dev" | "staging" | "prod"

#expirationForEnv: {
    dev: "30m"
    staging: "10m"
    prod: "2m"
}

#Hosts: {
    "dev-server": {
        _env: "dev"
        expiration: #expirationForEnv[_env]
        allow: {
            testuser: ["dev"]
        }
    }
}
```

## Advantages Over YAML

1. **Type Safety**: CUE catches errors at load time
2. **No Repetition**: Define once, reference everywhere
3. **Validation**: Built-in constraints ensure correctness
4. **Modularity**: Split large configs into logical files
5. **Documentation**: Schemas serve as inline documentation

## Migration from YAML

You can gradually migrate from YAML:

1. Start with a single `policy.yaml` file
2. Convert to `policy.cue` (syntax is similar)
3. Extract common patterns into separate files
4. Add schemas and validation constraints
5. Use CUE's advanced features as needed

The policy server supports both YAML and CUE simultaneously, so you can use whichever format suits your needs.
