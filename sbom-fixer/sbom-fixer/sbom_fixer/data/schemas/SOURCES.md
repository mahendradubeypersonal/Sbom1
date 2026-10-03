# Schema sources

Downloaded 2026-10-02. Refresh with `python tools/vendor_schemas.py` and commit the result.

| File | Source | Commit |
|---|---|---|
| cyclonedx/bom-1.2.schema.json | github.com/CycloneDX/specification schema/bom-1.2.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/bom-1.3.schema.json | github.com/CycloneDX/specification schema/bom-1.3.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/bom-1.4.schema.json | github.com/CycloneDX/specification schema/bom-1.4.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/bom-1.5.schema.json | github.com/CycloneDX/specification schema/bom-1.5.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/bom-1.6.schema.json | github.com/CycloneDX/specification schema/bom-1.6.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/bom-1.7.schema.json | github.com/CycloneDX/specification schema/bom-1.7.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/spdx.schema.json | github.com/CycloneDX/specification schema/spdx.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/jsf-0.82.schema.json | github.com/CycloneDX/specification schema/jsf-0.82.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| cyclonedx/cryptography-defs.schema.json | github.com/CycloneDX/specification schema/cryptography-defs.schema.json | `1ce97b2a7b8cf2429da248560d2aa671c6bce74a` |
| spdx/spdx-2.2.schema.json | github.com/spdx/spdx-spec (development/v2.2.2) schemas/spdx-schema.json | `4694d1fe63ecd269262c26bd4370d4e11e6f7f8f` |
| spdx/spdx-2.3.schema.json | github.com/spdx/spdx-spec (v2.3) schemas/spdx-schema.json | `aadf3b0b8dbbabdb4d880b0fc714255fea436ff7` |

Notes:

- The SPDX 2.2 schema comes from the 2.2.2 patch release. The original v2.2 schema wraps every property in a top-level `Document` object, so real SPDX 2.2 JSON files fail against it.
- SPDX 2.2.2 accepts both `PACKAGE-MANAGER` and `PACKAGE_MANAGER` as external reference categories, so no rename is needed when going from 2.3 to 2.2.
