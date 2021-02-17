# AVclass Service

Consumes Anti-Virus tags (`av.virus_name`) and extracts family, behaviour, and
platform information
using [AVclass2](https://github.com/malicialab/avclass/tree/master/avclass2).

## Configuration

The service has no parameters, but relies on the following files, as described
in the AVclass2 documentation.

* [`avclass_/data/avclass.tagging`](avclass_/data/avclass.tagging) - Tag aliases
* [`avclass_/data/avclass.expansion`](avclass_/data/avclass.expansion) - Implied tags
* [`avclass_/data/avclass.taxonomy`](avclass_/data/avclass.taxonomy) - Tag categories 

These configurations differ from defaults provided by AVclass2 in that they
were generated using a large quantity of VirusTotal submissions. Configuration
should be periodically updated to ensure that new malware families and
behaviours are correctly extracted.