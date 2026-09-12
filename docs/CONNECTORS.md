# Connector registry and plugin contract

The public registry makes connectors discoverable without letting a filename or URL silently choose
a destination resource.

```bash
polymorph connectors
polymorph connectors --output connector-manifests.json
```

Built-in manifests currently describe CSV, JSON/JSON5, Excel, Parquet, SQL database and HTTP JSON
connectors. A manifest lists endpoint roles, schemes, content kinds, extensions, features, auth modes,
limitations and any optional dependency extra.

## Resolution rules

Source files are classified from bounded byte and structure evidence. Their suffix is not the parser
authority. The accepted file identity is handed to the connector so a later path swap is rejected.

Destinations are never inferred. Supply either a destination connector object or an explicit spec:

```python
from polymorph import ConnectorSpec

csv_export = ConnectorSpec.destination("csv", path="./out/customers.csv")
database = ConnectorSpec.destination(
    "database",
    url="postgresql+psycopg://service@db.example/application",
    table="customers",
    schema="public",
)
```

Credentials should be references resolved by the connector's secret provider. Registry output and
factory errors never serialize connector configuration.

## Third-party entry points

Plugin loading is opt-in because importing an entry point executes third-party Python code. Normal
registry construction and `polymorph connectors` list only built-ins. A host must call
`registry.load_entry_points()` or pass `--plugins` explicitly.

Package metadata:

```toml
[project.entry-points."polymorph.connectors"]
acme-crm = "acme_polymorph:connector_plugin"
```

Plugin object:

```python
from polymorph.connector_registry import (
    ConnectorManifest,
    ConnectorPlugin,
    EndpointRole,
)


def connector_plugin():
    return ConnectorPlugin(
        manifest=ConnectorManifest(
            connector_id="acme-crm",
            display_name="Acme CRM",
            roles=(EndpointRole.SOURCE, EndpointRole.DESTINATION),
            schemes=("https",),
            features=("schema.read", "records.read", "records.write"),
            auth_modes=("credential_reference",),
            limitations=("Remote API quotas are deployment-specific.",),
            provider="acme",
        ),
        source_factory=create_source,
        destination_factory=create_destination,
    )
```

Factories receive the explicit configuration mapping and return an object implementing the source
or destination connector protocol. Configuration is intentionally opaque to the registry.

## Conformance kit

The built-in static check opens no endpoint and consumes no records:

```python
from polymorph.conformance import assert_connector_conformant
from polymorph.connector_registry import EndpointRole

report = assert_connector_conformant(connector, EndpointRole.DESTINATION, manifest=manifest)
```

It checks immutable `ConnectorCapabilities`, role/method consistency, schema inspection, record
iteration or writes, atomic batch method claims and plugin API version. Passing this static contract
is necessary, not sufficient. Connector packages should additionally test:

1. Bounded lazy source iteration with a generator that fails if consumed ahead of demand.
2. Exact request- or file-byte budgets rather than row-count approximations.
3. `NOT_COMMITTED`, `UNKNOWN` and committed-prefix `PARTIAL` failures at each write boundary.
4. Idempotency across scalar, batch, restart and lost-acknowledgement paths when advertised.
5. Schema drift, destination resource identity and credential-reference failures.
6. Oversized responses, pagination cycles, parser bombs and cancellation.

Do not advertise a security boundary merely because an interface exists. Host-specific containment,
transaction and witnessing claims require the matching host evidence.
