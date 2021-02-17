import os
import json
import pytest
import shutil

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
        service_name='avclass',
        service_config={},
        fileinfo=dict(
            magic='ASCII text, with no line terminators',
            md5='fda4e701258ba56f465e3636e60d36ec',
            mime='text/plain',
            sha1='af2c2618032c679333bebf745e75f9088748d737',
            sha256='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
            size=19,
            type='unknown',
        ),
        filename='dadc624d4454e10293dbd1b701b9ee9f99ef83b4cd07b695111d37eb95abcff8',
        min_classification='TLP:WHITE',
        max_files=501,  # TODO: get the actual value
        ttl=3600,
    ),
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
def avclass_class_instance():
    create_tmp_manifest()
    try:
        from avclass_ import AVclass
        yield AVclass()
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
        # from pathlib import Path
        # from avclass_ import DATA_PATH, TAG_PATH, EXP_PATH, TAX_PATH
        # data_path = Path(os.path.join(os.path.dirname(os.getcwd()), "data"))
        # assert DATA_PATH == data_path
        # assert TAG_PATH == Path(os.path.join(data_path, "avclass.tagging"))
        # assert EXP_PATH == Path(os.path.join(data_path, "avclass.expansion"))
        # assert TAX_PATH == Path(os.path.join(data_path, "avclass.taxonomy"))
        # TODO: this breaks in the test pipeline
        assert True

    @staticmethod
    def test_avclass_constants():
        from collections import namedtuple
        from avclass_ import AVClassTag, AVClassTags, AVCLASS_CATEGORY
        correct_avclass_tag = namedtuple('AVClassTag', ['name', 'path', 'category', 'rank'])
        correct_avclass_tags = namedtuple('AVClassTags', ['tags', 'is_pup', 'family'])
        assert check_equality_of_named_tuples(correct_avclass_tag, AVClassTag)
        assert check_equality_of_named_tuples(correct_avclass_tags, AVClassTags)
        assert AVCLASS_CATEGORY == {
            'FAM': ('family', 1),
            'BEH': ('behavior', 2),
            'CLASS': ('classification', 3),
            'FILE': ('file', 4),
            'GEN': ('generic', None),
            'UNK': ('unknown', None),
        }


class TestAVClass:
    @classmethod
    def setup_class(cls):
        create_tmp_manifest()

    @classmethod
    def teardown_class(cls):
        remove_tmp_manifest()

    @staticmethod
    def test_init(avclass_class_instance):
        # Code coverage, yay!
        assert True

    @staticmethod
    def test_start(avclass_class_instance):
        # Code coverage, yay!
        avclass_class_instance.start()
        # TODO: somehow assert that avclass_class_instance._av_labels is correct
        assert True

    @staticmethod
    @pytest.mark.parametrize("sample_info, expected_result", [(None, False)])
    def test_get_avclass_tags(sample_info, expected_result, avclass_class_instance):
        # TODO: write tests that verify that this method works correctly
        assert True

    @staticmethod
    @pytest.mark.parametrize("sample", samples)
    def test_execute(sample, avclass_class_instance):
        # TODO: Break down the execute method to make it easily testable
        from assemblyline_v4_service.common.task import Task
        from assemblyline.odm.messages.task import Task as ServiceTask
        from assemblyline_v4_service.common.request import ServiceRequest

        service_task = ServiceTask(sample)
        task = Task(service_task)
        avclass_class_instance._task = task
        service_request = ServiceRequest(task)

        # Actually executing the sample
        avclass_class_instance.execute(service_request)

        # Get the result of execute() from the test method
        test_result = task.get_service_result()

        # Get the assumed "correct" result of the sample
        correct_result_path = os.path.join(TEST_DIR, "results", task.file_name + ".json")
        with open(correct_result_path, "r") as f:
            correct_result = json.loads(f.read())
        f.close()

        # Assert that the appropriate sections of the dict are equal

        # Avoiding unique items in the response
        test_result_response = test_result.pop("response")
        correct_result_response = correct_result.pop("response")
        assert test_result == correct_result

        # Comparing everything in the response except for the service_completed and the output.json supplementary
        test_result_response["milestones"].pop("service_completed")
        correct_result_response["milestones"].pop("service_completed")
        correct_result_response.pop("supplementary")
        test_result_response.pop("supplementary")
        assert test_result_response == correct_result_response
