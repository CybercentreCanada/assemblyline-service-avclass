from typing import Optional, Dict, Any
import json

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection
from assemblyline_v4_service.common.result import BODY_FORMAT

class AVclass(ServiceBase):
    def __init__(self, config: Optional[Dict] = None) -> None:
        super().__init__(config)

    def start(self):
        pass

    def execute(self, request: ServiceRequest) -> Dict[str, Any]:
        pass
