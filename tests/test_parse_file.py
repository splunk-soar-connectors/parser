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
from copy import deepcopy
from email.message import EmailMessage
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from soar_sdk.apis.artifact import Artifact
from soar_sdk.apis.container import Container
from soar_sdk.exceptions import SoarAPIError

from src.app import ExtractIocOutput, ExtractIocParams, parse_file

run_action = parse_file.__wrapped__
VAULT_ID = "a" * 40
ATTACHMENT_ID = "b" * 40
FILE_HASH = "1234567890abcdef1234567890abcdef"  # pragma: allowlist secret


@pytest.fixture
def client(tmp_path):
    email_path = tmp_path / "sample.eml"
    attachment = SimpleNamespace(metadata={"sha256": "c" * 64})
    source = SimpleNamespace(path=str(email_path), name="sample.eml", metadata={})
    saved = []

    def save(artifact):
        saved.append(deepcopy(artifact))
        return len(saved)

    client = SimpleNamespace(
        container=SimpleNamespace(create=Mock(return_value=77)),
        artifact=SimpleNamespace(create=Mock(side_effect=save)),
        vault=SimpleNamespace(
            get_attachment=Mock(
                side_effect=lambda vault_id: (
                    [source] if vault_id == VAULT_ID else [attachment]
                )
            ),
            add_attachment=Mock(return_value=ATTACHMENT_ID),
        ),
        set_summary=Mock(),
        set_message=Mock(),
        saved=saved,
        email_path=email_path,
    )
    return client


def write_email(client, attachments=0, headers=True, body=None):
    mail = EmailMessage()
    if headers:
        mail["From"] = "a@example.com"
        mail["To"] = "b@example.org"
    mail["Subject"] = "sample"
    mail.set_content(
        body if body is not None else f"https://example.com 1.2.3.4 {FILE_HASH}"
    )
    for index in range(attachments):
        mail.add_attachment(
            f"contents {index}".encode(),
            maintype="application",
            subtype="octet-stream",
            filename=f"sample{index}.bin",
        )
    client.email_path.write_text(mail.as_string())


def email_params(**overrides):
    return ExtractIocParams(
        **{"vault_id": VAULT_ID, "file_type": "email", "container_id": 77, **overrides}
    )


def summary(client):
    return client.set_summary.call_args.args[0].model_dump()


def test_omitted_defaults_are_optional_in_manifest_and_applied_at_runtime():
    params = ExtractIocParams()
    schema = ExtractIocParams._to_json_schema()
    for name, expected in {
        "parse_domains": True,
        "run_automation": True,
        "is_structured": False,
        "keep_raw": False,
        "severity": "medium",
        "custom_remap_json": "{}",
        "remap_cef_fields": "Do not apply CEF -> CIM remapping, only apply custom remap",
    }.items():
        assert getattr(params, name) == expected
        assert schema[name]["default"] == expected
        assert schema[name]["required"] is False


@pytest.mark.parametrize("enabled", [True, False])
def test_text_domain_and_automation_flags(client, enabled):
    overrides = {} if enabled else {"parse_domains": False, "run_automation": False}
    run_action(
        ExtractIocParams(
            text="https://example.com", file_type="txt", container_id=77, **overrides
        ),
        client,
    )
    assert (
        any(
            artifact["cef"].get("destinationDnsDomain") == "example.com"
            for artifact in client.saved
        )
        is enabled
    )
    assert all(artifact["run_automation"] is enabled for artifact in client.saved)


@pytest.mark.parametrize("enabled", [True, False])
def test_email_extracts_all_body_iocs_and_honors_automation_and_tags(client, enabled):
    write_email(client, attachments=1)
    run_action(
        email_params(
            parse_domains=enabled,
            run_automation=enabled,
            artifact_tags="review, second-tag",
            severity="high",
        ),
        client,
    )
    cef = [artifact["cef"] for artifact in client.saved]
    assert any(item.get("requestURL") == "https://example.com" for item in cef)
    assert any(item.get("sourceAddress") == "1.2.3.4" for item in cef)
    assert any(item.get("fileHash") == FILE_HASH for item in cef)
    assert (
        any(item.get("destinationDnsDomain") == "example.com" for item in cef)
        is enabled
    )
    assert any(
        item.get("vaultId") == ATTACHMENT_ID and item.get("fileHashSha256") == "c" * 64
        for item in cef
    )
    assert all(
        artifact["run_automation"] is enabled
        and artifact["tags"] == ["review", "second-tag"]
        and artifact["severity"] == "high"
        for artifact in client.saved
    )
    assert summary(client) == {
        "artifacts_found": len(client.saved),
        "artifacts_ingested": len(client.saved),
        "container_id": 77,
    }


@pytest.mark.parametrize("limit", [1, 2, 3, 50])
def test_email_limit_is_shared_by_attachments_and_iocs(client, limit):
    write_email(client, attachments=2)
    run_action(email_params(max_artifacts=limit, run_automation=False), client)
    counts = summary(client)
    assert len(client.saved) == min(limit, counts["artifacts_found"])
    assert counts["artifacts_ingested"] == len(client.saved)
    assert counts["artifacts_found"] > 3
    assert client.vault.add_attachment.call_count == min(limit, 2)
    assert all(
        artifact["name"] == "Vault Artifact"
        for artifact in client.saved[: min(limit, 2)]
    )


def test_email_attachment_without_iocs_is_saved_and_counted(client):
    write_email(client, attachments=1, headers=False, body="No indicators here")
    run_action(email_params(), client)
    assert len(client.saved) == 1
    assert client.saved[0]["name"] == "Vault Artifact"
    assert summary(client) == {
        "artifacts_found": 1,
        "artifacts_ingested": 1,
        "container_id": 77,
    }


def test_email_headers_retain_first_casing_custom_names_and_repeated_values(client):
    client.email_path.write_text(
        "from: a@example.com\nTo: b@example.com\nReceived: first\nreceived: second\nRECEIVED: third\nX-Custom-Header: retained\n\nbody\n"
    )
    result = run_action(email_params(), client)
    assert result.model_dump(by_alias=True, exclude_none=True) == {
        "from": "a@example.com",
        "To": "b@example.com",
        "Received": ["first", "second", "third"],
        "X-Custom-Header": "retained",
    }
    assert "action_result.data.*.Received" in {
        field["data_path"] for field in ExtractIocOutput._to_json_schema()
    }


def test_email_container_retains_legacy_sdi_and_saves_artifacts_separately(client):
    write_email(client)
    run_action(email_params(container_id=None, label="events"), client)
    container = client.container.create.call_args.args[0]
    assert container["source_data_identifier"] == VAULT_ID
    assert container["run_automation"] is False
    assert "artifacts" not in container
    assert all(artifact["container_id"] == 77 for artifact in client.saved)


def test_reprocessing_email_uses_stable_artifact_identifiers(client):
    write_email(client, attachments=1)
    run_action(email_params(), client)
    first = {artifact["source_data_identifier"] for artifact in client.saved}
    client.saved.clear()
    run_action(email_params(), client)
    assert {artifact["source_data_identifier"] for artifact in client.saved} == first


@pytest.mark.parametrize("fail_at", ["parse", "container", "vault", "artifact", None])
def test_email_cleans_temporary_files_on_success_and_failures(
    client, tmp_path, monkeypatch, fail_at
):
    write_email(client, attachments=1)
    mime_dir = tmp_path / "mime"
    mime_dir.mkdir()
    monkeypatch.setattr(
        "soar_sdk.extras.email.processor.tempfile.mkdtemp",
        lambda **kwargs: str(mime_dir),
    )
    if fail_at == "parse":
        monkeypatch.setattr(
            "src.email_processor.ParserEmailProcessor._handle_mail_object",
            Mock(side_effect=ValueError("failed")),
        )
    elif fail_at == "container":
        client.container.create.side_effect = ValueError("failed")
    elif fail_at == "vault":
        client.vault.add_attachment.side_effect = ValueError("failed")
    elif fail_at == "artifact":
        client.artifact.create.side_effect = ValueError("failed")
    if fail_at:
        with pytest.raises(ValueError, match="failed"):
            run_action(email_params(container_id=None, label="events"), client)
        client.set_summary.assert_not_called()
    else:
        run_action(email_params(container_id=None, label="events"), client)
    assert not mime_dir.exists()


@pytest.mark.parametrize("email", [True, False])
def test_artifact_api_failure_fails_the_action_after_container_creation(client, email):
    responses = [{"id": 77}, {"message": "invalid artifact"}]
    client.client = SimpleNamespace(headers={"X-CSRFToken": "test"})
    client.post = Mock(
        side_effect=lambda *args, **kwargs: SimpleNamespace(
            json=lambda: responses.pop(0)
        )
    )
    client.container = Container(client)
    client.container.set_executing_asset("1")
    client.artifact = Artifact(client)
    if email:
        write_email(client, body="1.2.3.4")
        params = email_params(container_id=None, label="events")
    else:
        params = ExtractIocParams(text="1.2.3.4", file_type="txt", label="events")
    with pytest.raises(SoarAPIError, match="invalid artifact"):
        run_action(params, client)
    assert [call.args[0] for call in client.post.call_args_list] == [
        "rest/container",
        "rest/artifact",
    ]
    assert "artifacts" not in client.post.call_args_list[0].kwargs["json"]
    client.set_summary.assert_not_called()


def test_existing_artifact_response_counts_as_a_successful_save(client):
    client.client = SimpleNamespace(headers={"X-CSRFToken": "test"})
    client.post = Mock(
        return_value=SimpleNamespace(json=lambda: {"existing_artifact_id": 88})
    )
    client.artifact = Artifact(client)
    run_action(
        ExtractIocParams(text="1.2.3.4", file_type="txt", container_id=77), client
    )
    assert summary(client)["artifacts_ingested"] == 1


@pytest.mark.parametrize("parse_domains", [True, False])
def test_html_email_extracts_link_image_and_refresh_urls(client, parse_domains):
    mail = EmailMessage()
    mail["From"] = "a@example.com"
    mail.set_content(
        """<html><head><meta http-equiv="refresh" content="0; url=https://refresh.example.net"></head><body><a href="https://link.example.org">link</a><img src="https://image.example.org/a.png"><a href="mailto:person@mail.example.net?subject=test">mail</a>1.2.3.4</body></html>""",
        subtype="html",
    )
    client.email_path.write_text(mail.as_string())
    run_action(email_params(parse_domains=parse_domains), client)
    urls = {
        artifact["cef"]["requestURL"]
        for artifact in client.saved
        if "requestURL" in artifact["cef"]
    }
    domains = {
        artifact["cef"]["destinationDnsDomain"]
        for artifact in client.saved
        if "destinationDnsDomain" in artifact["cef"]
    }
    assert {
        "https://link.example.org",
        "https://image.example.org/a.png",
        "https://refresh.example.net",
    } <= urls
    assert any(
        artifact["cef"].get("sourceAddress") == "1.2.3.4" for artifact in client.saved
    )
    if parse_domains:
        assert {
            "link.example.org",
            "image.example.org",
            "refresh.example.net",
            "mail.example.net",
        } <= domains
    else:
        assert not domains


def test_missing_optional_vault_hash_metadata_does_not_lose_attachment(client):
    write_email(client, attachments=1)
    get_attachment = client.vault.get_attachment.side_effect

    def fail_metadata_lookup(vault_id):
        if vault_id != VAULT_ID:
            raise SoarAPIError("metadata unavailable")
        return get_attachment(vault_id)

    client.vault.get_attachment.side_effect = fail_metadata_lookup
    run_action(email_params(), client)
    assert any(
        artifact["cef"].get("vaultId") == ATTACHMENT_ID for artifact in client.saved
    )
    assert summary(client)["artifacts_ingested"] == len(client.saved)
