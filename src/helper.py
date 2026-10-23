# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import json
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.exceptions import ActionFailure
from soar_sdk.logging import getLogger

logger = getLogger()


class ParseResult:
    def __init__(self) -> None:
        self.status = True
        self.message = ""

    def set_status(self, status: bool, message: str = "") -> bool:
        self.status = status
        self.message = message
        return status


class ParserContext:
    def __init__(self) -> None:
        self._done = False

    def save_progress(self, message: str) -> None:
        logger.progress(message)

    def debug_print(self, *values: Any) -> None:
        logger.debug(" ".join(map(str, values)))

    def _dump_error_log(self, error: Exception) -> None:
        logger.error(str(error))

    def _get_error_message_from_exception(self, error: Exception) -> str:
        if len(error.args) > 1:
            return f"Error Code: {error.args[0]}. Error Message: {error.args[1]}"
        return f"Error Message: {error.args[0] if error.args else error}"


def parse_custom_mapping(serialized: str) -> dict[str, Any]:
    try:
        parsed = json.loads(serialized)
    except Exception as error:
        raise ActionFailure(
            f"Error: custom_remap_json parameter is not valid json. {error}"
        ) from error
    if not isinstance(parsed, dict):
        raise ActionFailure("Error: custom_remap_json parameter is not a dictionary")
    return parsed


def apply_remap(
    artifacts: list[dict[str, Any]], mapping: dict[str, Any]
) -> list[dict[str, Any]]:
    if not mapping:
        return artifacts
    for artifact in artifacts:
        artifact["cef"] = {
            mapping.get(key, key): value for key, value in artifact["cef"].items()
        }
    return artifacts


def save_artifacts(
    soar: SOARClient, artifacts: list[dict[str, Any]], container_id: int
) -> int:
    saved = 0
    for artifact in artifacts:
        artifact["container_id"] = container_id
        if not soar.artifact.create(artifact):
            raise ActionFailure("Artifact creation did not return an artifact ID")
        saved += 1
    return saved
