import os
import shutil

from assemblyline.common import forge
from assemblyline_client.v4_client.client import Client as Client4
from assemblyline_v4_service.updater.updater import ServiceUpdater

classification = forge.get_classification()


class AVClassUpdateServer(ServiceUpdater):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def import_update(
        self,
        files_sha256: str,
        al_client: Client4,
        source: str,
        default_classification: str = None,
    ):
        assert len(files_sha256) == 1
        shutil.move(files_sha256[0][0], os.path.join(self.latest_updates_dir, f"{source}.json"))
        self.log.info(f"Finished moving {source}.json to {self.latest_updates_dir}")
        return


if __name__ == "__main__":
    with AVClassUpdateServer() as server:
        server.serve_forever()
