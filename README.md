[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_avclass-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-avclass)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-avclass)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-avclass)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-avclass)](./LICENSE)

# AVClass Service

This service consumes Anti-Virus tags (`av.virus_name`) and extracts family, behavior, and platform information based on [AVClass2](https://github.com/malicialab/avclass/tree/master/avclass2).

## Service Details

The service relies on the following files, as described
in the AVClass2 documentation.

- [`data/avclass.tagging`](data/avclass.tagging) - Tag aliases
- [`data/avclass.expansion`](data/avclass.expansion) - Implied tags
- [`data/avclass.taxonomy`](data/avclass.taxonomy) - Tag categories

These configurations differ from defaults provided by AVClass2 in that they
were generated using a large quantity of VirusTotal submissions. Configuration files
should be periodically updated to ensure that new malware families and behaviors are correctly extracted.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Avclass \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-avclass

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service AVClass

Ce service consomme des balises antivirus (`av.virus_name`) et extrait des informations sur la famille, le comportement et la plate-forme en se basant sur [AVClass2](https://github.com/malicialab/avclass/tree/master/avclass2).

## Détails du service

Le service s'appuie sur les fichiers suivants, tels que décrits
dans la documentation AVClass2.

- [`data/avclass.tagging`](data/avclass.tagging) - Alias de balises
- [`data/avclass.expansion`](data/avclass.expansion) - Balises implicites
- [`data/avclass.taxonomy`](data/avclass.taxonomy) - Catégories de balises

Ces configurations diffèrent des valeurs par défaut fournies par AVClass2 dans la mesure où elles ont été générées à l'aide d'une grande quantité de données Virus.
qu'elles ont été générées en utilisant une grande quantité de soumissions VirusTotal. Les fichiers de configuration
doivent être régulièrement mis à jour pour garantir que les nouvelles familles de logiciels malveillants et les nouveaux comportements sont correctement extraits.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Avclass \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-avclass

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
