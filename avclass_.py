import json
from collections import namedtuple
from pathlib import Path
from typing import Optional, Dict, Any
from itertools import groupby

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

AVCLASS_CATEGORY = {
    'FAM': ('family', 1),
    'BEH': ('behavior', 2),
    'CLASS': ('classification', 3),
    'FILE': ('file', 4),
    'GEN': ('generic', None),
    'UNK': ('unknown', None),
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

    def _get_avclass_tags(self, sample_info):
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

    def execute(self, request: ServiceRequest) -> Optional[Dict[str, Any]]:
        result = Result()
        request.result = result

        tags = request.task.tags.get('av.virus_name')
        if not tags:
            return

        sample_info = SampleInfo(request.md5, request.sha1, request.sha256,
                                 [(f'av{i}', label) for i, label in enumerate(tags)], [])
        self.log.debug(f'SampleInfo: {sample_info}')
        av_tags = self._get_avclass_tags(sample_info)
        if av_tags is None:
            return

        body = {'is_pup': av_tags.is_pup}
        tags = dict()
        if av_tags.family is not None:
            title = f'AVclass extracted malware family: {av_tags.family}'
            body['family'] = av_tags.family
            tags['attribution.family'] = [av_tags.family]
        else:
            title = 'AVclass was unable to extract a malware family'
        section = ResultSection(title, json.dumps(body),
                                body_format=BODY_FORMAT.KEY_VALUE,
                                tags=tags)

        for category, tag_group in groupby(sorted(av_tags.tags,
                                                  key=lambda t: AVCLASS_CATEGORY_ORDER.index(t.category)),
                                           key=lambda t: t.category):
            tag_group = sorted(tag_group, key=lambda t: t.rank, reverse=True)
            tag_table = [{'name': tag.name,
                          'category': AVCLASS_CATEGORY[category][0],
                          'path': tag.path,
                          'rank': tag.rank}
                         for tag in tag_group]
            heur_id = AVCLASS_CATEGORY[category][1]

            tag_section = ResultSection(
                f'AVclass extracted {AVCLASS_CATEGORY[category][0]} tags',
                body=json.dumps(tag_table),
                body_format=BODY_FORMAT.TABLE,
                heuristic=Heuristic(heur_id) if heur_id is not None else None)

            if category == 'BEH':
                for tag in tag_group:
                    tag_section.add_tag('file.behaviour', tag.name)

            section.add_subsection(tag_section)

        result.add_section(section)
