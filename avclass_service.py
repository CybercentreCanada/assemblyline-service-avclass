import json
from collections import namedtuple
from itertools import groupby
from pathlib import Path
from typing import Any, AnyStr, Dict, Iterator, List, Optional

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT, Heuristic, Result, ResultSection
from avclass_common import AVLabels, Expansion, SampleInfo, Taxonomy, Translation
from avclass_importer import AVClassImporter
from pkg_resources import resource_filename

DATA_PATH = Path(resource_filename(__name__, "data"))
TAG_PATH = DATA_PATH / "avclass.tagging"
EXP_PATH = DATA_PATH / "avclass.expansion"
TAX_PATH = DATA_PATH / "avclass.taxonomy"
MAL_PATH = DATA_PATH / "malpedia.json"

AVClassTag = namedtuple("AVClassTag", ["name", "path", "category", "rank"])
AVClassTags = namedtuple("AVClassTags", ["tags", "is_pup", "family"])

# Mapping of category abbreviation => (family name, heuristic ID (optional), result section tag type (optional))
AVCLASS_CATEGORY = {
    "FAM": ("family", 1, "attribution.family"),
    "CLASS": ("classification", 2, "attribution.category"),
    "BEH": ("behavior", 3, "file.behavior"),
    "FILE": ("file", 4, None),
    "GEN": ("generic", None, None),
    "UNK": ("unknown", None, None),
}
AVCLASS_CATEGORY_ORDER = ["FAM", "CLASS", "BEH", "FILE", "GEN", "UNK"]


class AVClass(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self._av_labels = None
        self.base_data = None
        self.external_data = None
        self.importer = None

    def start(self, update: AnyStr = None) -> None:
        self.log.debug("Creating AVLabels object")
        self.base_data = (
            Translation(TAG_PATH),
            Expansion(EXP_PATH),
            Taxonomy(TAX_PATH),
        )
        if not update and not self.external_data:
            # import baseline malpedia
            self.importer = AVClassImporter(MAL_PATH)
        elif update:
            self.importer = AVClassImporter(update)
        if self.importer:
            self.external_data = self.importer.update_avlabels(*self.base_data)

    def _get_avclass_tags(
        self, md5: str, sha1: str, sha256: str, labels: List[str]
    ) -> Optional[AVClassTags]:
        """
        Gets AVClass tags from a list of AV labels.

        :param md5: MD5 hash of file
        :param sha1: SHA1 hash of file
        :param sha256: SHA256 hash of file
        :param labels: AV labels from "av.virus_name" result tags
        :return: `AVClassTags` or `None` if no tags were extracted
        """
        sample_info = SampleInfo(
            md5, sha1, sha256, [(f"av{i}", label) for i, label in enumerate(labels)], []
        )
        self.log.debug(f"SampleInfo: {sample_info}")

        tokens = self._av_labels.get_sample_tags(sample_info)
        tags = self._av_labels.rank_tags(tokens)
        if not tags:
            return None

        avc_tags = tuple(
            AVClassTag(tag, *self._av_labels.taxonomy.get_info(tag), rank)
            for tag, rank in tags
        )

        # Extract malware family name
        families = sorted(
            [(t.name, t.rank) for t in avc_tags if t.category == "FAM"],
            key=lambda f: f[1],
            reverse=True,
        )
        family = families[0][0] if families else None

        return AVClassTags(
            avc_tags, self._av_labels.is_pup(tags, self._av_labels.taxonomy), family
        )

    def _get_category_section(
        self, category: str, tags: Iterator[AVClassTag]
    ) -> ResultSection:
        """
        Gets a `ResultSection` for a list of tags from a single category.

        Result contains table with AVClass tag information in descending order by rank.

        :param category: Category of tags
        :param tags: Tags belonging to category
        :return: `ResultSection`
        """
        tags = sorted(tags, key=lambda t: t.rank, reverse=True)

        category_name, heur_id, tag_type = AVCLASS_CATEGORY[category]
        tag_table = [
            {
                "name": tag.name,
                "category": category_name,
                "path": tag.path,
                "rank": tag.rank,
            }
            for tag in tags
        ]

        subsection = ResultSection(
            f"AVClass extracted {len(tags)} {category_name} tags",
            body=json.dumps(tag_table),
            body_format=BODY_FORMAT.TABLE,
            heuristic=Heuristic(heur_id) if heur_id is not None else None,
        )
        if tag_type is not None:
            for tag in tags:
                subsection.add_tag(tag_type, tag.name)
        return subsection

    def _get_category_sections(self, tags: List[AVClassTag]) -> Iterator[ResultSection]:
        """
        Returns a `ResultSection` for each category of AVClass tags.

        :param tags: AVClass tags
        :return: A `ResultSection` for each AVClass tag category
        """
        # Sort tags by category for grouping
        tags = sorted(tags, key=lambda t: AVCLASS_CATEGORY_ORDER.index(t.category))

        for category, category_tags in groupby(tags, key=lambda t: t.category):
            yield self._get_category_section(category, category_tags)

    def _get_result_section(
        self,
        file_type: AnyStr,
        family: Optional[str],
        is_pup: bool,
        use_malpedia: bool,
    ) -> Optional[ResultSection]:
        """
        Returns a `ResultSection` for AVClass tags.

        :param family: Malware family name extracted by AVClass
        :param is_pup: Whether AVClass detected PUP
        :return: A `ResultSection`
        """
        body = {"is_pup": is_pup}
        section_tags = dict()
        if family is not None:
            family = family.lower()
            common_name = self.importer.get_common_name(family, file_type, use_malpedia)
            title = f"AVClass extracted malware family: {common_name}"
            body["family"] = common_name
            alt_names = self._get_alt_names(family, file_type, use_malpedia)
            if common_name.lower() != family:
                # This is the name that the common name is derived from, we should place it
                # at the front of the alt_names list
                alt_names.insert(0, family)
            if alt_names:
                body["aka"] = ", ".join(alt_names)
            section_tags["attribution.family"] = [family]
            actors = self.importer.get_actors(family, file_type, use_malpedia)
            if actors:
                body["actors"] = ", ".join(actors)
                section_tags["attribution.actor"] = actors
        else:
            title = "AVClass was unable to extract a malware family"
        section = ResultSection(
            title,
            json.dumps(body),
            body_format=BODY_FORMAT.KEY_VALUE,
            tags=section_tags,
            heuristic=Heuristic(1) if family is not None else None,
        )
        return section

    def _get_alt_names(
        self, family: AnyStr, file_type: AnyStr, use_malpedia: bool
    ) -> List:
        # alt_names is an alphabetically sorted list of translated names and malpedia names
        translation = self.base_data[0]._src_map
        alt_names = [
            key.lower() for key, value in translation.items() if value == {family}
        ]
        malpedia_names = self.importer.get_alt_names(family, file_type, use_malpedia)
        if malpedia_names:
            alt_names = list(set(alt_names + malpedia_names))
        alt_names.sort()
        return alt_names

    def execute(self, request: ServiceRequest) -> Optional[Dict[str, Any]]:
        # Create AVLabels object
        use_malpedia = request.get_param("include_malpedia_dataset")
        if use_malpedia:
            self._av_labels = AVLabels(*self.external_data)
        else:
            self._av_labels = AVLabels(*self.base_data)
        result = Result()
        request.result = result

        # Get AV labels from previous services
        av_labels = request.task.tags.get("av.virus_name")
        if not av_labels:
            return

        # Extract AVClass tags
        av_tags = self._get_avclass_tags(
            request.md5, request.sha1, request.sha256, av_labels
        )
        if av_tags is None:
            return

        # Build results
        section = self._get_result_section(
            request.file_type, av_tags.family, av_tags.is_pup, use_malpedia
        )
        for tag_section in self._get_category_sections(av_tags.tags):
            section.add_subsection(tag_section)

        result.add_section(section)

    def _load_rules(self) -> None:
        """
        Load Malpedia families file. This function will check the updates directory and try to load the latest
        Malpedia families file. If not successful, it will try older versions of the Malpedia families file.
        """
        try:
            rules = self.rules_list
            if rules:
                if Path(rules[0]).exists():
                    self.start(rules[0])
                else:
                    self.log.error(
                        f"No valid {self.name} 'malpedia.json' file found at {rules[0]}"
                    )
            else:
                self.log.error(
                    "AVClass didn't process the Malpedia file. Check if the service can reach the updater."
                )
        except Exception as e:
            self.log.error(
                f"No valid {self.name} 'malpedia.json' file found. Reason: {e}"
            )
