import json
from copy import deepcopy
from pathlib import Path
from typing import AnyStr, List, Optional, Tuple

from avclass_common import AVLabels, Expansion, Taxonomy, Translation
from pkg_resources import resource_filename


class AVClassImporter:
    # Imports Malpedia families
    def __init__(self, file: AnyStr) -> None:
        self.actors = {}
        self.types = []
        with open(file, "r") as f:
            self._malpedia = json.load(f)

    def update_avlabels(
        self, translations: Translation, expansions: Expansion, taxonomy: Taxonomy
    ) -> Tuple[Translation, Expansion, Taxonomy]:
        translations = deepcopy(translations)
        expansions = deepcopy(expansions)
        taxonomy = deepcopy(taxonomy)
        for entry in self._malpedia:
            family = self._malpedia[entry]
            type = entry.split(".")[0].lower()
            if type not in self.types:
                self.types.append(type)
            name = entry.split(".")[1].lower()
            if name.startswith("unidentified"):
                continue
            taxonomy.add_tag(f"FAM:{name.lower()}")
            alt_names = family.get("alt_names")
            actors = family.get("attribution")
            if len(alt_names) > 0:
                for alias in alt_names:
                    alias = alias.lower().replace(" ", "_")
                    translations.add_rule(alias.lower(), [name])
            if "_" in name:
                translations.add_rule(name.replace("_", ""), [name])
            if len(actors) > 0:
                self.actors[name] = actors
        return (translations, expansions, taxonomy)

    def get_actors(
        self, family: AnyStr, file_type: AnyStr, use_malpedia: bool = True
    ) -> List:
        if use_malpedia:
            name = self._check_type(family, file_type)
            if name:
                return self._malpedia[name]["attribution"]
            if family in self.actors:
                return self.actors[family]
        return []

    def get_common_name(
        self, family: AnyStr, file_type: AnyStr, use_malpedia: bool = True
    ) -> AnyStr:
        if use_malpedia:
            name = self._check_type(family, file_type)
            if name:
                return self._malpedia[name]["common_name"]
        return family.title()

    def get_alt_names(
        self, family: AnyStr, file_type: AnyStr, use_malpedia: bool = True
    ) -> List:
        if use_malpedia:
            name = self._check_type(family, file_type)
            if name:
                alt_names = self._malpedia[name]["alt_names"]
                return [name.lower() for name in alt_names]
        return []

    def _check_type(self, family: AnyStr, file_type: AnyStr) -> Optional[str]:
        prefix = None
        if "windows" in file_type:
            prefix = "win"
        else:
            for type in self.types:
                if type in file_type:
                    prefix = type
        if prefix:
            name = f"{prefix}.{family}"
            if name in self._malpedia:
                return name
        return None


if __name__ == "__main__":
    DATA_PATH = Path(resource_filename(__name__, "data"))
    TAG_PATH = DATA_PATH / "avclass.tagging"
    EXP_PATH = DATA_PATH / "avclass.expansion"
    TAX_PATH = DATA_PATH / "avclass.taxonomy"
    MAL_PATH = DATA_PATH / "malpedia.json"

    base_data = (Translation(TAG_PATH), Expansion(EXP_PATH), Taxonomy(TAX_PATH))
    importer = AVClassImporter(MAL_PATH)
    external_data = importer.update_avlabels(*base_data)
    # Create AVLabels object
    av_labels = AVLabels(*external_data)
