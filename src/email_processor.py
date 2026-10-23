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
import email
import re
import time
from dataclasses import dataclass
from html import unescape
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from bs4 import BeautifulSoup, UnicodeDammit
from soar_sdk.abstract import SOARClient
from soar_sdk.extras.email import EmailProcessor, ProcessEmailContext
from soar_sdk.extras.email.processor import validate_url
from soar_sdk.extras.email.utils import URI_REGEX, clean_url, get_file_contains, is_ip
from soar_sdk.logging import getLogger
from soar_sdk.shims.phantom.vault import PhantomVault

from .helper import save_artifacts

if TYPE_CHECKING:
    from .app import ExtractIocParams

logger = getLogger()


@dataclass
class ProcessedEmail:
    headers: dict[str, Any]
    container_id: int
    artifacts_found: int
    artifacts_ingested: int


class ParserEmailProcessor(EmailProcessor):
    def _extract_urls_domains(
        self, file_data: str, urls: set[str], domains: set[str]
    ) -> None:
        # SDK 6.1.2 calls a missing phantom.get_host_from_url shim here.
        soup = BeautifulSoup(file_data, "html.parser")
        uris = []
        mailtos = []
        for attribute in ("href", "src", "action"):
            for tag in soup.find_all(True, attrs={attribute: True}):
                uri = tag[attribute]
                if not isinstance(uri, str):
                    continue
                uris.append(clean_url(tag.get_text()))
                if attribute == "href" and uri.startswith("mailto:"):
                    mailtos.append(uri)
                else:
                    uris.append(uri)
        for meta in soup.find_all("meta", attrs={"http-equiv": True, "content": True}):
            directive, content = meta["http-equiv"], meta["content"]
            if (
                isinstance(directive, str)
                and directive.lower() == "refresh"
                and isinstance(content, str)
            ):
                uris.extend(re.findall(URI_REGEX, content))
        uris.extend(
            clean_url(uri) for uri in re.findall(URI_REGEX, unescape(file_data))
        )

        for uri in uris:
            try:
                validate_url(uri)
                domain = urlsplit(uri).hostname
            except ValueError:
                continue
            if self._config["extract_urls"]:
                urls.add(uri)
            if self._config["extract_domains"] and domain and not is_ip(domain):
                domains.add(domain)
        if self._config["extract_domains"]:
            for uri in mailtos:
                domain = uri.partition("@")[2].partition("?")[0]
                if domain and not is_ip(domain):
                    domains.add(domain)

    def attachment_artifact(
        self, attachment: dict[str, Any], container_id: int
    ) -> dict[str, Any]:
        file_path = attachment["file_path"]
        file_name = attachment.get("file_name") or Path(file_path).name
        vault_id = self.context.soar.vault.add_attachment(
            container_id=container_id,
            file_location=file_path,
            file_name=file_name,
            metadata={"action_name": self.context.action_name or "extract ioc"},
        )
        if not vault_id:
            raise ValueError("Attachment creation did not return a vault ID")
        cef = dict(attachment.get("meta_info", {}))
        cef.update(
            {
                "fileName": file_name,
                "vaultId": vault_id,
                "cs6": vault_id,
                "cs6Label": "Vault ID",
            }
        )
        try:
            vault_items = self.context.soar.vault.get_attachment(vault_id=vault_id)
        except Exception as error:
            logger.debug(f"Could not retrieve attachment hashes: {error}")
            vault_items = []
        if vault_items:
            metadata = vault_items[0].metadata
            for name, key in (
                ("fileHashSha256", "sha256"),
                ("fileHashSha1", "sha1"),
                ("fileHashMd5", "md5"),
            ):
                if metadata.get(key):
                    cef[name] = metadata[key]
        artifact = {"name": "Vault Artifact", "cef": cef}
        contains = get_file_contains(file_path)
        if contains:
            artifact["cef_types"] = {"vaultId": contains, "cs6": contains}
        return artifact

    def prepare_artifacts(self, artifacts: list[dict[str, Any]]) -> None:
        for artifact in artifacts:
            self._set_sdi(artifact)
        for artifact in artifacts:
            cef = artifact.get("cef", {})
            parent_guid = cef.pop("parentGuid", None)
            if parent_guid in self._guid_to_hash:
                cef["parentSourceDataIdentifier"] = self._guid_to_hash[parent_guid]
            cef.pop("emailGuid", None)


def process_email(
    soar: SOARClient,
    params: "ExtractIocParams",
    file_path: str,
    app_id: str,
    tags: list[str],
) -> ProcessedEmail:
    vault_id = params.vault_id
    if not vault_id:
        raise ValueError("A vault ID is required to process email")
    email_text = UnicodeDammit(Path(file_path).read_bytes()).unicode_markup
    if not email_text:
        raise ValueError("Could not read email file contents from the vault")
    message = email.message_from_string(email_text)
    headers: dict[str, Any] = {}
    normalized: dict[str, str] = {}
    for key, value in message.items():
        name = normalized.setdefault(key.lower(), key)
        if name not in headers:
            headers[name] = value
        elif isinstance(headers[name], list):
            headers[name].append(value)
        else:
            headers[name] = [headers[name], value]

    context = ProcessEmailContext(
        soar=soar,
        vault=PhantomVault(soar),
        app_id=app_id,
        folder_name="parser",
        is_hex=False,
        action_name="extract ioc",
    )
    processor = ParserEmailProcessor(
        context,
        {
            "extract_attachments": True,
            "extract_domains": params.parse_domains,
            "extract_hashes": True,
            "extract_ips": True,
            "extract_urls": True,
        },
    )
    try:
        processor._set_email_id_contains(vault_id)
        status, error, results = processor._int_process_email(
            email_text, vault_id, time.time()
        )
        if not status or not results:
            raise ValueError(error or "Failed to process email")
        result = results[0]
        container_id = params.container_id
        if container_id is None:
            container = result["container"]
            # Parser historically deduplicates email containers by vault ID alone.
            container.update(
                {
                    "source_data_identifier": vault_id,
                    "label": params.label,
                    "severity": params.severity.lower(),
                    "run_automation": False,
                }
            )
            container_id = soar.container.create(container)

        files = result.get("files", [])
        artifacts = result.get("artifacts", [])
        artifacts_found = len(files) + len(artifacts)
        if params.max_artifacts is not None:
            files = files[: params.max_artifacts]
            artifacts = artifacts[: params.max_artifacts - len(files)]
        artifacts_to_save = [
            processor.attachment_artifact(attachment, container_id)
            for attachment in files
        ]
        artifacts_to_save.extend(artifacts)
        for artifact in artifacts_to_save:
            artifact.update(
                {
                    "container_id": container_id,
                    "severity": params.severity.lower(),
                    "run_automation": params.run_automation,
                    "tags": tags,
                }
            )
        processor.prepare_artifacts(artifacts_to_save)
        artifacts_ingested = save_artifacts(soar, artifacts_to_save, container_id)
        return ProcessedEmail(
            headers, container_id, artifacts_found, artifacts_ingested
        )
    finally:
        processor._del_tmp_dirs()
