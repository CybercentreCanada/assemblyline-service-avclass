from collections import namedtuple
from itertools import groupby
import json
from pathlib import Path
from typing import Optional, Dict, Any, List, Iterator

from pkg_resources import resource_filename

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, BODY_FORMAT, Heuristic

from avclass.avclass2.lib.avclass2_common import SampleInfo, AvLabels

DATA_PATH = Path(resource_filename(__name__, 'data'))
TAG_PATH = DATA_PATH / 'avclass.tagging'
EXP_PATH = DATA_PATH / 'avclass.expansion'
TAX_PATH = DATA_PATH / 'avclass.taxonomy'

AVClassTag = namedtuple('AVClassTag', ['name', 'path', 'category', 'rank'])
AVClassTags = namedtuple('AVClassTags', ['tags', 'is_pup', 'family'])

# Mapping of category abbreviation => (family name, heuristic ID (optional), result section tag type (optional))
AVCLASS_CATEGORY = {
    'FAM': ('family', 1, None),
    'BEH': ('behavior', 2, 'file.behavior'),
    'CLASS': ('classification', 3, None),
    'FILE': ('file', 4, None),
    'GEN': ('generic', None, None),
    'UNK': ('unknown', None, None),
}
AVCLASS_CATEGORY_ORDER = ['FAM', 'BEH', 'CLASS', 'FILE', 'GEN', 'UNK']


class AVclass(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)
        self._av_labels = None

    def start(self) -> None:
        self.log.debug('Creating AvLabels object')

        # Create AvLabels object
        self._av_labels = AvLabels(tag_file=TAG_PATH, exp_file=EXP_PATH,
                                   tax_file=TAX_PATH)

    def _get_avclass_tags(self, md5: str, sha1: str, sha256: str, labels: List[str]) -> Optional[AVClassTags]:
        """
        Gets AVclass tags from a list of AV labels.

        :param md5: MD5 hash of file
        :param sha1: SHA1 hash of file
        :param sha256: SHA256 hash of file
        :param labels: AV labels from "av.virus_name" result tags
        :return: `AVClassTags` or `None` if no tags were extracted
        """
        sample_info = SampleInfo(md5, sha1, sha256,
                                 [(f'av{i}', label) for i, label in enumerate(labels)], [])
        self.log.debug(f'SampleInfo: {sample_info}')

        tokens = self._av_labels.get_sample_tags(sample_info)
        tags = self._av_labels.rank_tags(tokens)
        if not tags:
            return None

        avc_tags = tuple(AVClassTag(tag,
                                    *self._av_labels.taxonomy.get_info(tag),
                                    rank)
                         for tag, rank in tags)

        # Extract malware family name
        families = sorted([(t.name, t.rank) for t in avc_tags
                           if t.category == 'FAM'],
                          key=lambda f: f[1], reverse=True)
        family = families[0][0] if families else None

        return AVClassTags(avc_tags, self._av_labels.is_pup(tags, self._av_labels.taxonomy), family)

    def _get_category_section(self, category: str, tags: Iterator[AVClassTag]) -> ResultSection:
        """
        Gets a `ResultSection` for a list of tags from a single category.

        Result contains table with AVclass tag information in descending order by rank.

        :param category: Category of tags
        :param tags: Tags belonging to category
        :return: `ResultSection`
        """
        tags = sorted(tags, key=lambda t: t.rank, reverse=True)

        category_name, heur_id, tag_type = AVCLASS_CATEGORY[category]
        tag_table = [{'name': tag.name,
                      'category': category_name,
                      'path': tag.path,
                      'rank': tag.rank}
                     for tag in tags]

        section = ResultSection(
            f'AVclass extracted {len(tags)} {category_name} tags',
            body=json.dumps(tag_table), body_format=BODY_FORMAT.TABLE,
            heuristic=Heuristic(heur_id) if heur_id is not None else None)
        if tag_type is not None:
            for tag in tags:
                section.add_tag(tag_type, tag.name)

        return section

    def _get_category_sections(self, tags: List[AVClassTag]) -> Iterator[ResultSection]:
        """
        Returns a `ResultSection` for each category of AVclass tags.

        :param tags: AVClass tags
        :return: A `ResultSection` for each AVclass tag category
        """
        # Sort tags by category for grouping
        tags = sorted(tags, key=lambda t: AVCLASS_CATEGORY_ORDER.index(t.category))

        for category, category_tags in groupby(tags, key=lambda t: t.category):
            yield self._get_category_section(category, category_tags)

    def _get_result_section(self, family: Optional[str], is_pup: bool) -> Optional[ResultSection]:
        """
        Returns a `ResultSection` for AVclass tags.

        :param family: Malware family name extracted by AVclass
        :param is_pup: Whether AVclass detected PUP
        :return: A `ResultSection`
        """
        body = {'is_pup': is_pup}
        section_tags = dict()
        if family is not None:
            title = f'AVclass extracted malware family: {family}'
            body['family'] = family
            section_tags['attribution.family'] = [family]
        else:
            title = 'AVclass was unable to extract a malware family'
        section = ResultSection(title, json.dumps(body),
                                body_format=BODY_FORMAT.KEY_VALUE,
                                tags=section_tags)
        return section

    def execute(self, request: ServiceRequest) -> Optional[Dict[str, Any]]:
        result = Result()
        request.result = result

        # Get AV labels from previous services
        av_labels = request.task.tags.get('av.virus_name')
        if not av_labels:
            return

        # Extract AVclass tags
        av_tags = self._get_avclass_tags(request.md5, request.sha1, request.sha256, av_labels)
        if av_tags is None:
            return

        # Build results
        section = self._get_result_section(av_tags.family, av_tags.is_pup)
        for tag_section in self._get_category_sections(av_tags.tags):
            section.add_subsection(tag_section)

        result.add_section(section)
