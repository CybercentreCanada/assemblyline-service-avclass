import json
import os
import shutil
from collections import namedtuple
from random import randint, shuffle

import pytest
from assemblyline.odm.messages.task import Task as ServiceTask
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import BODY_FORMAT
from assemblyline_v4_service.common.task import Task
from avclass.common import AVLabels, Expansion, Taxonomy
from avclass.avclass import (
    AVCLASS_CATEGORY,
    AVCLASS_CATEGORY_ORDER,
    DATA_PATH,
    EXP_PATH,
    TAG_PATH,
    TAX_PATH,
    AVClass,
    AVClassTag,
    AVClassTags,
)

# Getting absolute paths, names and regexes
TEST_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(TEST_DIR)
SERVICE_CONFIG_NAME = "service_manifest.yml"
SERVICE_CONFIG_PATH = os.path.join(ROOT_DIR, SERVICE_CONFIG_NAME)
TEMP_SERVICE_CONFIG_PATH = os.path.join("/tmp", SERVICE_CONFIG_NAME)


# Samples that we will be sending to the service
samples = [
    dict(
        sid=1,
        metadata={},
        service_name="avclass",
        service_config={},
        fileinfo=dict(
            magic="ASCII text, with no line terminators",
            md5="fda4e701258ba56f465e3636e60d36ec",
            mime="text/plain",
            sha1="af2c2618032c679333bebf745e75f9088748d737",
            sha256="dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8",
            size=19,
            type="unknown",
        ),
        filename="dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8",
        min_classification="TLP:WHITE",
        max_files=501,  # TODO: get the actual value
        ttl=3600,
    ),
]


# Test parameters: AV labels, AVClassTags
avclass_labels = [
    (
        ["W32.Sality.PE", "Win.Virus.Sality-1067"],
        [
            "sality",
            (
                ("sality", "FAM:sality", "FAM", 2),
                ("windows", "FILE:os:windows", "FILE", 2),
            ),
            False,
        ],
    ),
    (
        [
            "Virus.Win32.Nimnul.lse3",
            "Virus.Win32.Nimnul.e",
            "Win32.Ramnit.N",
            "Win32.Ramnit.N (B)",
        ],
        (
            "wapomi",
            (
                ("virus", "CLASS:virus", "CLASS", 2),
                ("wapomi", "FAM:wapomi", "FAM", 2),
                ("windows", "FILE:os:windows", "FILE", 3),
            ),
            False,
        ),
    ),
    (
        [
            "W32/Poison.CWKQ!tr.bdr",
            "W32.Backdoor.Poisonivy",
            "Win32:Agent-AAGI [Trj]",
            "Bck/Poison.E",
            "win/malicious_confidence_100% (W)",
            "Backdoor.Win32.PIvy.A",
        ],
        (
            "poison",
            (("poison", "FAM:poison", "FAM", 3),),
            False,
        ),
    ),
    (
        [
            "Program.Freemake.175",
            "a variant of Win32/Freemake.A potentially unwanted",
            "InstallCore",
            "PUP.Optional.Freemake",
            "Riskware/Freemake",
        ],
        (
            None,
            (
                ("grayware", "CLASS:grayware", "CLASS", 3),
                ("freemake", "UNK:freemake", "UNK", 4),
            ),
            True,
        ),
    ),
]

# Test parameters: Category, list of AVClassTag
avclass_category_tags = [
    (
        "FAM",
        [("poison", "FAM:poison", "FAM", 3), ("sality", "FAM:sality", "FAM", 2)],
    ),  # Family section
    (
        "CLASS",
        [
            ("grayware", "CLASS:grayware", "CLASS", 3),
            ("virus", "CLASS:virus", "CLASS", 2),
        ],
    ),  # Classification section
    ("BEH", [("downloader", "BEH:downloader", "BEH", 3)]),  # Behaviour section
    ("UNK", [("unknown", "UNK:unknown", "UNK", 3)]),  # Unknown section
]

# Test parameters: Category counts, List of AVClassTag
avclass_tags = []
for i in range(10):
    counts = {}
    tags = []
    for c in ["BEH", "FAM", "UNK", "FILE", "CLASS", "GEN"]:
        counts[c] = randint(0, 5)
        for i in range(counts[c]):
            tags.append(("unknown", f"{c}:unknown", c, randint(2, 5)))
    shuffle(tags)
    avclass_tags.append((counts, tags))

# Test parameters: File type, Family name, is PUP, use Malpedia?
avclass_results = [
    ("code/vbs", None, True, False),
    ("code/vbs", None, False, False),
    ("code/vbs", "emotet", True, False),
    ("code/vbs", "wapomi", False, False),
]


def create_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if not os.path.exists(temp_service_config_path):
        # Placing the service_manifest.yml in the tmp directory
        shutil.copyfile(SERVICE_CONFIG_PATH, temp_service_config_path)


def remove_tmp_manifest():
    temp_service_config_path = os.path.join("/tmp", SERVICE_CONFIG_NAME)
    if os.path.exists(temp_service_config_path):
        os.remove(temp_service_config_path)


@pytest.fixture
def target():
    create_tmp_manifest()
    try:
        yield AVClass()
    finally:
        remove_tmp_manifest()


def check_equality_of_named_tuples(this, that):
    if this._fields == that._fields:
        return True
    else:
        return False


class TestModule:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    def test_path_constants():
        assert DATA_PATH.is_dir()
        assert TAG_PATH.is_file()
        assert TAG_PATH.name.endswith(".tagging")
        assert EXP_PATH.is_file()
        assert EXP_PATH.name.endswith(".expansion")
        assert TAX_PATH.is_file()
        assert TAX_PATH.name.endswith(".taxonomy")

    @staticmethod
    def test_module_constants():
        AVClassTagT = namedtuple("AVClassTag", ["name", "path", "category", "rank"])
        AVClassTagsT = namedtuple("AVClassTags", ["tags", "is_pup", "family"])
        assert check_equality_of_named_tuples(AVClassTagT, AVClassTag)
        assert check_equality_of_named_tuples(AVClassTagsT, AVClassTags)
        assert AVCLASS_CATEGORY == {
            "FAM": ("family", 1, "attribution.family"),
            "CLASS": ("classification", 2, "attribution.category"),
            "BEH": ("behavior", 3, "file.behavior"),
            "FILE": ("file", 4, None),
            "GEN": ("generic", None, None),
            "UNK": ("unknown", None, None),
        }
        assert AVCLASS_CATEGORY_ORDER == ["FAM", "CLASS", "BEH", "FILE", "GEN", "UNK"]


class TestAVClass:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    def test_init(target):
        assert True

    @staticmethod
    @pytest.mark.parametrize("input, expected", avclass_labels)
    def test_get_avclass_tags(input, expected, target):
        target.start()
        target._av_labels = AVLabels(*target.base_data)
        family, tags, is_pup = expected

        result = target._get_avclass_tags("md5", "sha1", "sha256", input)
        assert result.family == family if family is not None else result.family is None
        assert result.is_pup == is_pup

        # Since configuration can change, only verify that a specific subset of tags has been extracted
        assert set(tags).intersection(set(map(tuple, result.tags))) == set(tags)

    @staticmethod
    @pytest.mark.parametrize("category, tags", avclass_category_tags)
    def test_get_category_section(category, tags, target):
        target.start()

        section = target._get_category_section(category, (AVClassTag(*t) for t in tags))

        assert AVCLASS_CATEGORY[category][0] in section.title_text
        assert section.body_format == BODY_FORMAT.TABLE
        assert len(json.loads(section.body)) == len(tags)

        if AVCLASS_CATEGORY[category][1] is None:
            assert section.heuristic is None
        else:
            assert section.heuristic is not None

        if category in ["BEH", "FAM", "CLASS"]:
            assert len(section.tags) > 0
        else:
            assert len(section.tags) == 0

    @staticmethod
    @pytest.mark.parametrize("cat_counts, tags", avclass_tags)
    def test_get_category_sections(cat_counts, tags, target):
        target.start()
        from avclass_service import AVCLASS_CATEGORY, AVCLASS_CATEGORY_ORDER, AVClassTag

        sections = target._get_category_sections([AVClassTag(*t) for t in tags])

        # Check sections in category order
        for category in AVCLASS_CATEGORY_ORDER:
            # Empty categories shouldn't have a section
            if cat_counts[category] == 0:
                continue

            section = next(sections)
            table = json.loads(section.body)
            assert AVCLASS_CATEGORY[category][0] == table[0]["category"]

            # Section should have only one category
            assert len(set([r["category"] for r in table])) == 1
            assert len(table) == cat_counts[category]

        # Verify all sections accounted for
        with pytest.raises(StopIteration):
            next(sections)

    @staticmethod
    @pytest.mark.parametrize("file_type, family, is_pup, use_malpedia", avclass_results)
    def test_get_result_section(file_type, family, is_pup, use_malpedia, target):
        target.start()

        section = target._get_result_section(file_type, family, is_pup, use_malpedia)
        assert section.body_format == BODY_FORMAT.KEY_VALUE
        body = json.loads(section.body)

        assert "is_pup" in body
        assert body["is_pup"] == is_pup

        if family is not None:
            assert "extracted" in section.title_text
            assert "family" in body
            assert body["family"].lower() == family
            assert section.tags.get("attribution.family", None) == [family]
        else:
            assert "unable to extract" in section.title_text
            assert "family" not in body

    @staticmethod
    @pytest.mark.parametrize("file_type, family, _, use_malpedia", avclass_results)
    def test_get_alt_names(file_type, family, _, use_malpedia, target):
        target.start()

        alt_names = target._get_alt_names(family, file_type, use_malpedia)
        if family == "emotet":
            assert alt_names == ["emotetcrypt", "geodo", "heodo"]
        elif family == "wapomi":
            assert alt_names == [
                "bototer",
                "jadtre",
                "loorp",
                "mikcer",
                "nimnul",
                "otwycal",
                "pikor",
                "pikorms",
                "protil",
                "qvod",
                "simfect",
                "vjadtre",
                "wali",
            ]
        else:
            assert alt_names == []

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, target):
        target.start()

        service_task = ServiceTask(sample)
        task = Task(service_task)
        task.service_config = {
            "include_malpedia_dataset": False,
        }
        target._task = task
        service_request = ServiceRequest(task)

        # Actually executing the sample
        target.execute(service_request)

        assert isinstance(target._av_labels, AVLabels)
        assert isinstance(target._av_labels.taxonomy, Taxonomy)
        assert isinstance(target._av_labels.expansions, Expansion)
        assert target._av_labels.avs is None
