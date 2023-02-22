# AVClass Service

Consumes Anti-Virus tags (`av.virus_name`) and extracts family, behavior, and
platform information based on [AVClass2](https://github.com/malicialab/avclass/tree/master/avclass2).

## Configuration

The service has no parameters, but relies on the following files, as described
in the AVClass2 documentation.

* [`data/avclass.tagging`](data/avclass.tagging) - Tag aliases
* [`data/avclass.expansion`](data/avclass.expansion) - Implied tags
* [`data/avclass.taxonomy`](data/avclass.taxonomy) - Tag categories

These configurations differ from defaults provided by AVClass2 in that they
were generated using a large quantity of VirusTotal submissions. Configuration
should be periodically updated to ensure that new malware families and
behaviors are correctly extracted.