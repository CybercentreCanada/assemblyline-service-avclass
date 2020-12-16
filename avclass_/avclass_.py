from typing import Optional, Dict, Any
import json
from pathlib import Path
from pkg_resources import resource_filename
from collections import namedtuple

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection
from assemblyline_v4_service.common.result import BODY_FORMAT

from avclass.avclass2.lib.avclass2_common import SampleInfo, AvLabels

AVC2_PATH = Path(resource_filename(__name__, 'avclass/avclass2'))
TAG_PATH = AVC2_PATH/'data/default.tagging'
EXP_PATH = AVC2_PATH/'data/default.expansion'
TAX_PATH = AVC2_PATH/'data/default.taxonomy'

AVClassTag = namedtuple('AVClassTag', ['name', 'path', 'category', 'rank'])
AVClassTags = namedtuple('AVClassTags', ['tags', 'is_pup', 'family'])

AVCLASS_CATEGORY = {
    'FAM': 'family',
    'BEH': 'behavior',
    'CLASS': 'classification',
    'FILE': 'file',
    'GEN': 'generic',
    'UNK': 'unknown',
}


class AVclass(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)

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

        return AVClassTags(avc_tags,
                           self._av_labels.is_pup(tags,
                                                  self._av_labels.taxonomy),
                           family)

    def execute(self, request: ServiceRequest) -> Dict[str, Any]:
        result = Result()
        request.result = result

        tags = request.task.tags.get('av.virus_name')
        if not tags:
            result.add_section(ResultSection('No AV labels'))
            return

        sample_info = SampleInfo(request.md5, request.sha1, request.sha256,
                                 [(f'av{i}', label) for i, label
                                  in enumerate(tags)], [])
        self.log.debug(f'SampleInfo: {sample_info}')
        av_tags = self._get_avclass_tags(sample_info)
        if av_tags is None:
            result.add_section(ResultSection('AVclass could not extract '
                                             'family information'))
            return

        section = ResultSection('AVclass extracted malware family: '
                                f'{av_tags.family}')
        section.set_body(json.dumps({'family': av_tags.family,
                                     'PUP?': av_tags.is_pup}),
                         BODY_FORMAT.KEY_VALUE)

        for tag in av_tags.tags:
            tag_section = ResultSection(f'AVclass extracted tag: {tag.name}')
            tag_section.set_body(
                json.dumps({'name': tag.name,
                            'category': AVCLASS_CATEGORY[tag.category],
                            'path': tag.path,
                            'rank': tag.rank}),
                BODY_FORMAT.KEY_VALUE)
            section.add_subsection(tag_section)

        result.add_section(section)
