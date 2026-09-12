# Independent public multilingual corpus v1 provenance

This corpus contains schema labels and manually assigned canonical correspondences, not source
records. It was authored before running the evaluated matcher and is not training input.

## Source groups

- `companies-house-company-profile-en`: factual field labels from the UK Companies House public API
  documentation. Companies House states that its public register data is available through its API
  and data products and that users remain responsible for data-protection and copyright compliance.
  Sources: https://developer.company-information.service.gov.uk/ and
  https://www.gov.uk/guidance/companies-house-data-products
- `insee-sirene-fr`: factual field labels from the French INSEE SIRENE variable description and
  open-data access documentation. No company records are redistributed. Sources:
  https://www.insee.fr/fr/information/3591226 and
  https://www.insee.fr/fr/statistiques/fichier/3711695/Description-liste-sirene-fr.pdf
- `destatis-genesis-de`: factual labels shown in the official GENESIS web-service documentation.
  GENESIS is available under Datenlizenz Deutschland - Namensnennung - Version 2.0. Source:
  https://www.destatis.de/DE/Service/OpenData/genesis-api-webservice-oberflaeche.html
- `peppol-billing-en`: a small set of factual business-term names used to test invoice terminology.
  No specification text or example invoice is redistributed. Source:
  https://docs.peppol.eu/poacc/billing/3.0/syntax/ubl-invoice/

## Separation and limitations

- Source groups are kept intact and are not split across training and evaluation.
- Labels were manually mapped to Polymorph's canonical demonstration schemas.
- The corpus tests terminology matching, not row parsing or universal business correctness.
- It is small and must not be described as a customer-quality benchmark.
- Future versions must use new source groups or later time slices rather than tuning this file.
