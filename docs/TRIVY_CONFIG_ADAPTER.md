# Adaptateur Trivy de configuration isolé

## Objet et autorité

`SEC-TRIVY-CONFIG-001` est un **adaptateur externe opt-in**, pas une source autonome de décision. Il n’est construit que si la politique sélectionnée contient ce contrôle *et* une section `external_tools.trivy` complète. Le résultat normalisé rejoint ensuite le moteur de politique déterministe versionné; ce moteur reste l’unique autorité qui produit `PASS`, `BLOCK`, `WAIVER_REQUIRED`, `ERROR` ou `NOT_EVALUATED`.

> Le binaire Trivy, les observations de couverture, le catalogue de domaines et toute capacité future d’IA ne peuvent ni modifier une politique, ni créer une waiver, ni approuver une livraison.

La commande officielle `trivy config` est conçue pour analyser des fichiers de configuration à la recherche de mauvaises configurations. Le mode filesystem, lui, peut activer par défaut des scanners de vulnérabilités et de secrets; cet adaptateur emploie donc la sous-commande dédiée et sélectionne explicitement le seul scanner `misconfig`. [1] [2]

| Élément | Contrat versionné |
|---|---|
| Identifiant d’implémentation | `SEC-TRIVY-CONFIG-001` |
| Contrat de domaine | `CONTROL-CONTAINER-IAC-TRIVY-CONFIG-001` |
| Politique d’activation fournie | `rules/trivy-config-policy.yaml` |
| Version de binaire exigée par cette politique | `0.74.0` |
| Domaine de conteneur déclaré | `DOMAIN-CONTAINER-SECURITY-001` |
| Domaine IaC déclaré | `DOMAIN-IAC-SECURITY-001` |
| Disposition de l’exemple de politique | `BLOCK` |

## Périmètre de fichiers et mise en scène

L’adaptateur n’invoque jamais Trivy sur la racine du dépôt cible. Il énumère d’abord les fichiers déjà présents dans l’inventaire borné de Before Deploy. Seuls les artefacts du tableau sont lus comme texte UTF-8 puis copiés sous le même chemin relatif dans un répertoire temporaire propre à l’adaptateur. Les fichiers exclus par l’inventaire, trop gros ou illisibles n’entrent pas dans cette étape.

| Inclus dans la copie isolée | État |
|---|---|
| Noms commençant par `Dockerfile` | Inclus comme catégorie `dockerfile` |
| Noms commençant par `Containerfile` | Inclus comme catégorie `dockerfile` |
| Fichiers ayant le suffixe `.tf` | Inclus comme catégorie `terraform` |
| Docker Compose, y compris `compose.yaml` | Exclu |
| Images, archives, registres et Docker daemon | Exclu |
| Terraform `tfvars`, plans, état, providers et `.terraform/` | Exclu |
| Helm, Kubernetes, CloudFormation et fichiers générés/exclus | Exclu |

Tout chemin source ou résultat qui ne peut pas être démontré comme restant sous sa racine attendue est rejeté. La copie ne suit pas un lien qui résoudrait hors du dépôt. Si aucune entrée admissible n’est disponible, le contrôle renvoie `NOT_APPLICABLE`; il ne lance alors aucun binaire, même si la politique référence Trivy.

Les mécanismes de suppression contrôlés par le dépôt ne sont pas admis. `.trivyignore` n’est pas copié et l’option `--ignorefile` pointe vers un fichier vide créé par l’adaptateur. Chaque forme reconnue de commentaire `trivy:ignore:` est neutralisée dans la copie tout en préservant les positions de ligne. Ainsi, une exception ne peut être exprimée que par une waiver Before Deploy exacte, liée au fingerprint, au digest du dépôt, à un approbateur et à une date d’expiration.

## Exécution contrôlée

Avant le scan, l’adaptateur appelle le binaire préinstallé avec `--version` et exige une correspondance exacte, à l’exception du préfixe `v`, avec la version de politique. Une absence de binaire, une sortie de version non reconnue, une divergence de version, un délai dépassé ou un démarrage impossible est une erreur explicite.

Le scan utilise une liste d’arguments construite par le code, sans shell, sans interpolation d’arguments provenant du dépôt, avec entrée standard et sorties de journal supprimées. Le processus enfant ne reçoit qu’un environnement minimal et un `HOME` temporaire; aucun secret d’environnement parent n’est transmis. La mise en scène, le cache, les modules et le rapport sont créés hors du dépôt cible.

```text
trivy config
  --format json
  --output <rapport-temporaire>
  --scanners misconfig
  --misconfig-scanners dockerfile,terraform
  --offline-scan
  --skip-check-update
  --skip-version-check
  --disable-telemetry
  --skip-vex-repo-update
  --tf-exclude-downloaded-modules
  --ignorefile <fichier-vide-contrôlé>
  --cache-dir <cache-temporaire>
  --module-dir <modules-temporaires-vides>
  <racine-mise-en-scène>
```

Cette invocation désactive les mises à jour de contrôles, la télémétrie et les entrées qui permettraient des règles, données, namespaces, variables Terraform, valeurs Helm, identifiants de registre ou configurations contrôlées par la cible. Elle demande en outre le mode hors ligne et exclut les modules Terraform téléchargés. Les contrôles de mauvaise configuration sont embarqués dans le binaire comme solution de repli utilisable en environnement isolé, tandis que les bases de vulnérabilités, VEX Hub et des mises à jour de contrôles sont des sources distinctes qui nécessitent normalement une connectivité. [1] [3]

> L’adaptateur ne tente jamais une installation, un téléchargement, une résolution de module ou un mode de scan alternatif. Une défaillance est retournée au moteur de politique, jamais masquée par un second essai réseau.

## Schéma normalisé et confidentialité

Le rapport JSON est lu uniquement depuis le fichier temporaire et seulement s’il est inférieur à la limite `max_report_bytes` de la politique. Le parseur exige une racine d’objet avec `SchemaVersion` positif et `Results` liste. Chaque résultat doit indiquer `Class: config`, une catégorie autorisée (`dockerfile` ou `terraform`) et une cible connue de la copie isolée. Chaque finding exige un `ID`, une sévérité reconnue et un `CauseMetadata.StartLine` strictement positif.

| Champ Trivy validé | Valeur conservée dans Before Deploy |
|---|---|
| `ID` | `upstream_rule_id`, après validation syntaxique |
| `Severity` | `upstream_severity` et sévérité interne (`CRITICAL` devient `BLOCKER`) |
| `Type` | `artifact_category` (`dockerfile` ou `terraform`) |
| `Target` et `CauseMetadata.StartLine` | chemin relatif et ligne de `Location` |
| `Message`, `Description`, `CauseMetadata.Resource`, code, extraits, URLs, références et suppressions | Délibérément rejetés et jamais rapportés |

Un rapport non UTF-8, trop volumineux, incomplet, contradictoire, hors périmètre, ou d’une forme non reconnue renvoie `ERROR`. Les sorties standard et erreur de Trivy ne sont ni stockées ni incluses dans JSON, Markdown ou SARIF.

## Utilisation opérationnelle

Une équipe provisionne le binaire Trivy par son processus de distribution approuvé, vérifie que `trivy --version` indique `0.74.0`, puis choisit explicitement le profil dédié. Le projet ne télécharge pas et n’installe pas Trivy au moment du scan.

```bash
uv run before-deploy scan /chemin/vers/depot \
  --policy rules/trivy-config-policy.yaml \
  --output-dir /tmp/before-deploy-trivy-config
```

Le profil dédié est distinct de `default-policy.yaml` et de `strict-ci-policy.yaml`. Le simple fait que Trivy soit présent sur `PATH` ne l’active pas. Dans ce profil, une erreur de l’adaptateur est requise et le moteur termine avec `ERROR` (code de sortie `20`); une finding non waived avec la disposition fournie conduit à `BLOCK` (code `10`).

## Limites et interprétation

Trivy documente que l’analyse Terraform couvre une analyse statique et possède des limites pour les sources de données, attributs calculés et informations de plan. La copie isolée de cet adaptateur resserre encore ce périmètre: elle ne fournit ni plans, ni variables externes, ni modules téléchargés, ni état cloud. [4]

Par conséquent, ce contrôle ne démontre pas la sécurité d’une image, l’exécution réussie d’un Dockerfile, la sécurité d’un runtime, l’identité d’un registre, la conformité, la configuration effectivement déployée, l’état du cloud, l’authentification IAM ou l’exhaustivité Terraform. Il fournit seulement l’évidence statique limitée que le Trivy préinstallé et épinglé a émise pour les artefacts mis en scène.

## Tests de sécurité du contrat

`tests/unit/test_trivy_config_adapter.py` utilise uniquement des exécutables factices. Il vérifie le contrôle de version, la liste d’arguments, l’environnement minimal, l’absence d’analyse de la racine cible, la mise en scène limitée, la neutralisation d’inline ignore, l’ignorance de `.trivyignore`, la normalisation Dockerfile et Terraform, la redaction JSON/Markdown/SARIF, l’absence de binaire, le délai, le rapport malformé et la fuite de chemin. Le corpus [`fixtures/trivy_config_calibration/`](../fixtures/trivy_config_calibration/) ajoute des entrées statiques sûres, vulnérables, ambiguës, avec suppression cible et hors périmètre; `tests/unit/test_trivy_calibration_fixtures.py` vérifie seulement leur périmètre et leur mise en scène. Aucun test ne lance Trivy réel, ne télécharge un bundle de contrôles ou une base, et n’exécute le code applicatif d’un fixture. La calibration réelle air-gap et toute adoption en branche protégée restent une revue humaine distincte.

## Références

[1]: https://trivy.dev/docs/latest/references/configuration/cli/trivy_config/ "Trivy — référence CLI config"
[2]: https://trivy.dev/docs/latest/references/configuration/cli/trivy_filesystem/ "Trivy — référence CLI filesystem"
[3]: https://trivy.dev/docs/latest/advanced/air-gap/ "Trivy — connectivité et contrôles embarqués"
[4]: https://trivy.dev/docs/latest/guide/coverage/iac/terraform/ "Trivy — couverture et limites Terraform"
