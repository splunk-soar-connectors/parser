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
import time
from pathlib import Path
from typing import Any

from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Param, Params
from soar_sdk.action_results import ActionOutput, OutputField
from soar_sdk.asset import BaseAsset
from soar_sdk.logging import getLogger

logger = getLogger()


class Asset(BaseAsset):
    pass


app = App(
    name="Parser",
    app_type="information",
    logo="logo_splunk.svg",
    logo_dark="logo_splunk_dark.svg",
    product_vendor="Splunk",
    product_name="Parser",
    publisher="Splunk",
    appid="4004f489-1826-44a1-af12-9c74eea82eb0",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
)


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    logger.info("Parser app is ready")


class ExtractIocParams(Params):
    vault_id: str | None = Param(
        description="Vault ID", primary=True, cef_types=["vault id"]
    )
    file_type: str | None = Param(
        description="Type of the file",
        value_list=["txt", "email", "pdf", "docx", "csv", "html"],
    )
    text: str | None = Param(description="Raw text from which to extract IOCs")
    is_structured: bool | None = Param(
        description="Use first row of CSV file as field names", default=False
    )
    label: str | None = Param(description="Add container to this label")
    max_artifacts: int | None = Param(description="Maximum number of artifacts")
    container_id: int | None = Param(
        description="Add created artifacts to this container"
    )
    remap_cef_fields: str | None = Param(
        description="Remap the CEF fields with new field names; Optionally, also apply an internal CEF -> CIM field name mapping. Note: (source|destination)Address will be mapped to (src|dest)_ip respectively instead of src|dest (not applicable to .eml filetype)",
        default="Do not apply CEF -> CIM remapping, only apply custom remap",
        value_list=[
            "Do not apply CEF -> CIM remapping, only apply custom remap",
            "Apply CEF -> CIM remapping before applying custom remap",
            "Apply custom remap and apply CEF -> CIM remapping after",
        ],
    )
    custom_remap_json: str | None = Param(
        description="Custom set of CEF field name mappings. This is a serialized json dictionary (json.dumps) of Key/Value pairs where Key is an existing field name and Value is the resultant name (not applicable to .eml filetype)",
        default="{}",
    )
    run_automation: bool | None = Param(
        description="Enable run_automation for newly created artifacts", default=True
    )
    severity: str | None = Param(
        description="Severity for the newly created artifacts", default="medium"
    )
    parse_domains: bool | None = Param(
        description="Parse domains from artifacts", default=True
    )
    artifact_tags: str | None = Param(
        description="Tags to add to artifacts (comma separated). Tag should only contain characters A-Z, a-z, 0-9, _, and -. Blank spaces will be ignored"
    )
    keep_raw: bool | None = Param(
        description="Save raw text to artifact", default=False
    )


class ExtractIocOutput(ActionOutput):
    Content_Language: str | None = OutputField(
        example_values=["en-US"], alias="Content-Language"
    )
    Content_Type: str | None = OutputField(
        example_values=[
            'multipart/alternative; boundary="0000000000005233b405c7737dbe"'
        ],
        alias="Content-Type",
    )
    Date: str | None = OutputField(example_values=["Mon, 19 Jul 2021 11:18:40 +0530"])
    From: str | None = OutputField(example_values=["xyz@xyz.com"])
    In_Reply_To: str | None = OutputField(
        example_values=[
            "<CAGUkOuok3+qiuH4rCNKf=6_a4qwRViq=1WTro1pB8zSVqEujog@mail.gmail.com>"  # pragma: allowlist secret
        ],
        alias="In-Reply-To",
    )
    MIME_Version: str | None = OutputField(example_values=["1.0"], alias="MIME-Version")
    Message_ID: str | None = OutputField(
        example_values=["<xyz@mail.gmail.com>"], alias="Message-ID"
    )
    References: str | None = OutputField(example_values=["<xyz@mail.gmail.com>"])
    Subject: str | None = OutputField(
        example_values=[
            "=?UTF-8?B?5paw44GX44GESUTF-8?B?MeOBpOOCkuS9v+eUqOOBl+OBpuOAgeS4gOaEj+OBruODquODs+OCr+ODreODvOOCq+ODq+OCouODiQ==?=\r\n\t="  # pragma: allowlist secret
        ]
    )
    Thread_Index: str | None = OutputField(
        example_values=["AQHWF83DD6R+qs4BTUSciZoeNB7NYw=="],  # pragma: allowlist secret
        alias="Thread-Index",
    )
    Thread_Topic: str | None = OutputField(
        example_values=[
            "\r\n\t=?utf-8?B?5ryi5a2XwqnCrMm40aDWjdue4KiK4K+14LWs4LyD4YCk4YSo4YeX4YqW4Y+M?=\r\n"  # pragma: allowlist secret
        ],
        alias="Thread-Topic",  # pragma: allowlist secret
    )
    To: str | None = OutputField(example_values=["xyz@xyz.com"])
    X_MS_Exchange_Organization_RecordReviewCfmType: str | None = OutputField(
        example_values=["0"],
        alias="X-MS-Exchange-Organization-RecordReviewCfmType",  # pragma: allowlist secret
    )
    X_MS_Exchange_Organization_SCL: str | None = OutputField(
        example_values=["-1"], alias="X-MS-Exchange-Organization-SCL"
    )
    X_MS_Has_Attach: str | None = OutputField(
        example_values=["yes"], alias="X-MS-Has-Attach"
    )
    X_MS_TNEF_Correlator: str | None = OutputField(
        example_values=["xyz"], alias="X-MS-TNEF-Correlator"
    )
    Received: str | None = OutputField(
        example_values=[
            "from mansh7fre.z21h3fdhjbvjhjhjjgqechox4fh.zx.internal.cloudapp.net ([20.77.122.17])\r\n        by smtp.test.com with ESMTPSA id t12-20020adff60c000000b002366ded5864sm7050556wrp.116.2022.10.31.06.25.08\r\n        for <sgdsg@test.com>\r\n        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);\r\n        Mon, 31 Oct 2022 06:25:08 -0700 (PDT)"  # pragma: allowlist secret
        ]
    )
    X_Received: str | None = OutputField(
        example_values=[
            "by 2002:a05:600c:3585:b0:3b4:a308:1581 with SMTP id p5-2drfh78uy6sadtd003b4a3081581mr18516488wmq.77.1667222709252;\r\n        Mon, 31 Oct 2022 06:25:09 -0700 (PDT)"
        ],
        alias="X-Received",
    )
    Return_Path: str | None = OutputField(
        example_values=["buhhjggj887@test.com"], alias="Return-Path"
    )
    IronPort_SDR: str | None = OutputField(
        example_values=[
            "635fccb7_90V6GckKA2l9BvDxvI24Rhw29Af6jLnJvUY0wqFQaa+Pbol\r\n W1pRHLHUcEmR9erE+mHJJjbWp/GmDYT8uGz13ig=="
        ],
        alias="IronPort-SDR",
    )
    Received_SPF: str | None = OutputField(
        example_values=[
            'None (mail6.hdds.com: no sender authenticity\r\n  information available from domain of\r\n  gvhjh@mail-wm1-f50.test.com) identity=helo;\r\n  client-ip=209.85.128.50; receiver=mail6.gghjc.com;\r\n  envelope-from="ysduj@ftdgc.com";\r\n  x-sender="gvhjh@mail-wm1-f50.test.com";\r\n  x-conformance=spf_only'
        ],
        alias="Received-SPF",
    )
    X_Amp_Result: str | None = OutputField(
        example_values=["UNKNOWN"], alias="X-Amp-Result"
    )
    IronPort_Data: str | None = OutputField(
        example_values=[
            "AgcvhadGfhgBsjdbnmsa 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"
        ],
        alias="IronPort-Data",
    )
    IronPort_PHdr: str | None = OutputField(
        example_values=[
            "QEslkmdkmd,sxcm:jkxsansam,xsmhjdds QEbwUCh8QSkl5oK+++Imq/EsTXaTcnF\r\n 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"
        ],
        alias="IronPort-PHdr",
    )
    X_IPAS_Result: str | None = OutputField(
        example_values=[
            "gssahjdxsauijn=xs0HMUQDKy19jfzKAVdFaHAEBASsBAQcBAQEFAQEEBAEBA?=\r\n =?us-ascii?q?gEJAYFmGIErAgEBAWOBLCsuBFCET4t/hRtYgkCDLoRQBSsCUQkrBhqDIIENg?=\r\n =?us-ascii?q?VYCASoEB2kCA4JVgyktgmQTgSw9CAcBAQEBAQEBAQEEAQMBAhIBBSYEBAEBA?=\r\n =?us-ascii?q?wSEdSE5AQgGCYQTAh0HAUsBAgECAQEBAQEDAgMBAQEBAQEDAQEBBAEBAQIBA?=\r\n =?us-ascii?q?QIEAwEBAQIQAQEYCRkHDg4FJIVoDYF6HAwTInxNAzgBAQEBAQEBAQEBAQEBA?=\r\n =?us-ascii?q?QEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBBAJ+KAEhFhEdAQQXHgMSRwIEGAkRA?=\r\n =?us-ascii?q?QUBV4F8AV+CbAEDHxEDA5w1gX4BIIEEQopCcIEVBQIDE4EBggkGBQMCAYREC?=\r\n =?us-ascii?q?hkoDWuBUwcCBwkBCIEpAwEBAQGBT4ccgkiER3ongimBS4IyEoFzgwWBB4MKM?=\r\n =?us-ascii?q?oI0BItXXgmBMDggYG2FdwQPGQMDAiEDRB0CBAUDIwUKAwsJCBM/BgMBAQwHP?=\r\n =?us-ascii?q?QQEDA8HGAMBAQ8kAQECAgIDBAcCAQMGAwwCAgEBAQUGDQMCAwgTAwIBAwUCA?=\r\n =?us-ascii?q?gQBAgQKCAECAgECBAUGAQIBCAUBBQoDBQkFAgQBAQIDBwQDCwYCBQIBAgMFA?=\r\n =?us-ascii?q?QIDAgEKBQIDAQIBAQMGBAQBAQIDAgIBBgICAQEDAwQDAQIEAgICBwIDAgEEA?=\r\n =?us-ascii?q?gECAwEBAQICAgICAgMDCQIIBwUBAgQBAgEEAwICAQIHAQICAQgDAwUFAgcPA?=\r\n =?us-ascii?q?wUDAQMDAgUPAwEGBQECAQICAgIEAggCBAUCBQMCBAIDAgIIAwIDAQIBBwQDB?=\r\n =?us-ascii?q?AEEAgQDDwQDBAIDAgIFAgICAgIFAgIDAQICAgICAgUCAwIBBQECAgECAgIEA?=\r\n =?us-ascii?q?QICBwQCAwEDBA4EAwICBwECAgEGAgcDAQIBBAMBAQQCBAECBQIEAQMGAgMBA?=\r\n =?us-ascii?q?woCAgMCAQECAwMFAwMCCAgCAwUCBAEBAgQDBAICCwEGAgcCAgMCAgQEBAEBA?=\r\n =?us-ascii?q?gEEBQIDAQIDAwkCAgMCBAICCgEBAQECAQcCBAcGAgUCAgIDAQICAgEDAgIBA?=\r\n =?us-ascii?q?QICChIBAQIDAwMEBgUDAgMFAgEVAQYCAQECAgMDAgYCAQIIAgQBBAUCAQIBA?=\r\n =?us-ascii?q?QICBAEIAgIBAQECAQICAwMCAQICAgQDAgEBAgECAgIDAgICAwICAQ8CBgYBA?=\r\n =?us-ascii?q?gICAgICAgICBgECAQIDAQIHAgQDAgECAgUCAgIDAQEGAgQLAQMCAgICAQYBA?=\r\n =?us-ascii?q?wEBAgUBAgICAwEBAwMEAwMLAwIMCAEFAQMBIAMCAggCBwIBBgMCAQ8DAgIDA?=\r\n =?us-ascii?q?gIBBAoCAwUCBAIBBAkHAgQBAgkDAgYCBwUYAQICBwQMCgEBAgIFBgIEAQECA?=\r\n =?us-ascii?q?wECAQECAwQCAwIEBQEFAgECBQICAgIBAQIFAgwBAgEDBAIEAgcCAgICAwECA?=\r\n =?us-ascii?q?gIBAgEDAwIDAQEBAwYGAgMEBAIDAwYCAgIDAQICAwIEDQIBBQICBgMCBAENB?=\r\n =?us-ascii?q?QUEBQQDAggBAgEBBwIEAgcJDgIBAgQBBQICAwICAQUCAQIEAwECAgICBQgFA?=\r\n =?us-ascii?q?wQBBAMVAwEBBAMCAQIBBAMCAwcDAgQEAwECAwQGBgEJAwICBgMCAgEBDQMEA?=\r\n =?us-ascii?q?gIBAgECAwQEBAICAgIBAgICAgMEAgIBAQMDAwICAgMEAgMDCwYKAQcCAgIDA?=\r\n =?us-ascii?q?gEFCwICAgMCAQEDBgMBBQIEAgIGAQIEAgICAgICAgMBAQMKBAIBAgMCAgYDB?=\r\n =?us-ascii?q?gIBAgECAQkFAgEJAwECAQMEAQMJAQICBAkCAwcFBAYEAgICAggCAg4DAwIBA?=\r\n =?us-ascii?q?QQCAgQDAgICCwIBAgcCBQEBAwUHAgIBAgIBBAMBCQQBAgIDAgEBAwMRAwMDA?=\r\n =?us-ascii?q?QQCAgUDAw0JBgICAQMCAwENAwMBAgECAwEFBRcDAgEIBwMTAwIBAQMCAQICA?=\r\n =?us-ascii?q?wYNAgIDAwMCAQIFAgQDAwEFAgEBAwEFAwIOAwIDAwMCBgECAQECAwMBDAQCA?=\r\n =?us-ascii?q?wEBAQEXAQIDAgQCAgEBAgUBBAMBAQIBAgMCAg4GAQQFDAUCAQIfAgIDAwEEB?=\r\n =?us-ascii?q?QICAggCAgIBAwMBAwMFAQIDBAICAQUEBgQCAgICAgICAQwClAoCDCsIBxUdJ?=\r\n =?us-ascii?q?z8KKIMvUF8ZgR0LPXuBAwIBAZE6EwqDVYwuVZIEjFsPHgkBBgJbgVJ8FxsNB?=\r\n =?us-ascii?q?YYYhV6LI4dJUIEWM4NlARKMU4YhkieGXW+OaHenTAIKBwYQIxKBWwyBXHBXX?=\r\n =?us-ascii?q?QEBOFxtTwMZD443g1uKfiE0OwIHCwEBAwmJYF4BAQ?="
        ],
        alias="X-IPAS-Result",
    )
    X_IronPort_AV: str | None = OutputField(
        example_values=[
            'E=Sophos;i="5.95,228,1661832000"; \r\n   d="pdf\'?scan\'208";a="17527695"'
        ],
        alias="X-IronPort-AV",
    )
    DKIM_Signature: str | None = OutputField(
        example_values=[
            "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=test.com; s=20210112;\r\n        h=mime-version:to:from:subject:date:message-id:from:to:cc:subject\r\n         :date:message-id:reply-to;\r\n        bh=G6MOWm8IxsWIXK+E9cSPXsZUV8kMF62PRajdB0itqYo=;\r\n        b=EuhoEvKCqFlTYYCZBZBEzUzLfQ4+a9YkucvjR+RL4ZtJowjnLImqQfPVk3Jb3eEqAo\r\n         yIRa4sJfs1y5VB21X14+d0KGiGd8ROfYkBmE3vLj5FmaOOKp5BHCQ7OOKfqwDlP/pxF3\r\n         AY/NZgYxHCjdOOUPRbLoZNNdqgeCoQ7YT1Q3Qyb7qXr/OgNCVzvVGvdjlnsXOVsXtGE0\r\n         ykWj6R8eQVp8zQ8snhFalrdP/aJstJa54e82bTb7rScJDoHIFwaLiTFtvDHEDEHV9Qd/\r\n         airADFSq28tbda8KQBPKfuwSnAMCYSuDiOS/VLmJzkAwxKXbyArdS7sLhpVJFPEk7t5H\r\n         lRSQ=="  # pragma: allowlist secret
        ],
        alias="DKIM-Signature",
    )
    IronPort_HdrOrdr: str | None = OutputField(
        example_values=[
            "A9a23:9U7lNq8V4jTDmL7ZUA1uk+AFI+orL9Y04lQ7vn2ZLiYlF/Bw9v\r\n re/sjzuiWVtN98Yh8dcLO7V5VoKEm0naKdirNhXotKMjOGhEKYaK9v6of4yyDtFmnU5odmuZ\r\n tIQuxbBMfrBVZ3yeT38GCDeeoI8Z2i/LqzjenTi01xSxpnApsM0y5iBh2FHlZNSA5KOJo8GP\r\n OnjfZ6mw=="  # pragma: allowlist secret
        ],
        alias="IronPort-HdrOrdr",
    )
    X_Gm_Message_State: str | None = OutputField(
        example_values=[
            "gjkwxWxdoK20dUSWBYLIn7gnobu5VoUCUYcraQo0EicpQQELl3HK5oG\r\n\t8wrn0qDdzJARTnQuR8t+qMQl5e6+8C3zQQ=="  # pragma: allowlist secret
        ],
        alias="X-Gm-Message-State",
    )
    X_Amp_File_Uploaded: str | None = OutputField(
        example_values=["False"], alias="X-Amp-File-Uploaded"
    )
    X_Google_Smtp_Source: str | None = OutputField(
        example_values=[
            "owqkSWSM6EI96NBN6wZMoTHH0X9sNIiQ/A/Xfw/kDRMmNqDF8efL+kFhpOjB8CWsBjI8i34hcmAWD2yA=="  # pragma: allowlist secret
        ],
        alias="X-Google-Smtp-Source",
    )
    Authentication_Results: str | None = OutputField(
        example_values=[
            "mail6.tgdd.com; spf=Pass smtp.mailfrom=ygdd@test.com; spf=None smtp.helo=dsds@mail-wm1-f50.test.com; dkim=pass (signature verified) header.i=@test.com; dmarc=pass (p=none dis=none) d=test.com"
        ],
        alias="Authentication-Results",
    )
    X_Amp_Original_Verdict: str | None = OutputField(
        example_values=["FILE UNKNOWN"], alias="X-Amp-Original-Verdict"
    )
    X_Google_DKIM_Signature: str | None = OutputField(
        example_values=[
            "v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n        d=1e100.net; s=20210112;\r\n        h=mime-version:to:from:subject:date:message-id:x-gm-message-state\r\n         :from:to:cc:subject:date:message-id:reply-to;\r\n        bh=G6MOWm8IxsWIXK+E9cSPXsZUV8kMF62PRajdB0itqYo=;\r\n        b=KZK25hKZcvCD6c/gBU7zzocEzqoOTNaAsayBZER10hTS6MU82iqd1mVo+YS137GuWT\r\n         yju6NgH4nouHvnPHC/9+Ka4YtgUh+aMQiJJ9FqoYjkJ1CDFbMBdAxC71ATJxeK3yLYuT\r\n         IsiDWAxufsz9oqoLwQBTzhm6To+4MbIGsdG5DJB4UM+Fojll7FRx/ChUo3aB7KIPW0pK\r\n         1VtgeNpqDq4ou+I1ukiAnqhylWMWbubHd6s37PT8jC1yo00tO7DqR8+ArfXRy4jODfBH\r\n         M4iXuvnBT5j4wO4UD/+y3wazJchEC/OcSSos2w0SYHRTlGYXEI7nYXXKwQH+4c4zz4L3\r\n         sQRg=="
        ],
        alias="X-Google-DKIM-Signature",
    )
    X_IronPort_Anti_Spam_Filtered: str | None = OutputField(
        example_values=["true"], alias="X-IronPort-Anti-Spam-Filtered"
    )
    X_MS_Exchange_Organization_AuthAs: str | None = OutputField(
        example_values=["Anonymous"], alias="X-MS-Exchange-Organization-AuthAs"
    )
    X_MS_Exchange_Organization_AuthSource: str | None = OutputField(
        example_values=["ILG1WNEX01.vcorp.ad.vrsn.com"],
        alias="X-MS-Exchange-Organization-AuthSource",
    )
    X_MS_Exchange_Processed_By_BccFoldering: str | None = OutputField(
        example_values=["15.01.2507.013"],
        alias="X-MS-Exchange-Processed-By-BccFoldering",
    )
    X_MS_Exchange_Transport_EndToEndLatency: str | None = OutputField(
        example_values=["00:00:00.4499410"],
        alias="X-MS-Exchange-Transport-EndToEndLatency",
    )
    X_MS_Exchange_Organization_AVStamp_Enterprise: str | None = OutputField(
        example_values=["1.0"], alias="X-MS-Exchange-Organization-AVStamp-Enterprise"
    )
    X_MS_Exchange_Organization_Network_Message_Id: str | None = OutputField(
        example_values=["cfc822d7-70b2-4fdf-a024-08dabb4356d5"],
        alias="X-MS-Exchange-Organization-Network-Message-Id",
    )


class ExtractIocSummary(ActionOutput):
    artifacts_found: int = OutputField(example_values=[13])
    artifacts_ingested: int = OutputField(example_values=[1])
    container_id: int = OutputField(column_name="Container ID", example_values=[1776])


@app.action(
    name="extract ioc",
    description="Create IOC artifacts from a file in the vault or raw text",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=ExtractIocSummary,
    verbose="Specify either text or vault_id. If text is used only file_types of csv, html, and txt can be selected. <br/><br/>If vault_id is used and the [file_type] is left blank, the app will try to determine what type of file it is on its own. <br/><br/> When parsing an email file (.eml), the <b>file_type</b> parameter must be set to <b>email</b>. <br/> <br/> <b>Label</b> or <b>Container ID</b> is mandatory to run an action. It will display an error message if both of them are not mentioned. <br/> <br/> <b> Caveats:</b> <ul><li>If the [file_type] you chose related to [vault_id] is incorrect, you will have an unexpected output scenario.</li></ul>",
)
def parse_file(
    params: ExtractIocParams, soar: SOARClient[ExtractIocSummary]
) -> ExtractIocOutput:
    from . import parser_const, parser_methods  # noqa: PLC0415
    from .helper import ParseResult, ParserContext, apply_remap, parse_custom_mapping  # noqa: PLC0415

    logger.progress("Parsing input for IOCs")
    if params.container_id is None and params.label is None:
        raise ValueError("A label must be specified if no container ID is provided")
    if params.container_id is not None and params.container_id <= 0:
        raise ValueError("Please provide a valid integer value in container_id")
    if params.vault_id and params.text:
        raise ValueError(
            "Either text can be parsed or a file from the vault can be parsed but both "
            "the 'text' and 'vault_id' parameters cannot be used simultaneously"
        )
    if params.text and params.file_type not in ("txt", "csv", "html"):
        raise ValueError(
            "When using text input, only csv, html, or txt file_type can be used"
        )
    if not (params.vault_id or params.text):
        raise ValueError(
            "Either 'text' or 'vault_id' must be submitted, both cannot be blank"
        )
    if params.max_artifacts is not None and params.max_artifacts <= 0:
        raise ValueError(
            "Please provide a valid non-zero positive integer value in max_artifacts"
        )

    custom_mapping = parse_custom_mapping(params.custom_remap_json or "{}")
    remap_mode = (params.remap_cef_fields or "").lower()
    severity = (params.severity or "medium").lower()
    tags = [
        tag.replace(" ", "")
        for tag in (params.artifact_tags or "").split(",")
        if tag.replace(" ", "")
    ]
    file_info: dict[str, Any] = {}
    if params.vault_id:
        vault_items = soar.vault.get_attachment(vault_id=params.vault_id)
        if not vault_items:
            raise ValueError("Could not retrieve file from the vault")
        vault_item = vault_items[0]
        file_type = params.file_type or vault_item.name.rsplit(".", 1)[-1]
        file_info = {
            "id": params.vault_id,
            "path": vault_item.path,
            "name": vault_item.name,
            "type": file_type,
        }

    if params.vault_id and params.file_type == "email":
        import email  # noqa: PLC0415
        from bs4.dammit import UnicodeDammit  # noqa: PLC0415
        from soar_sdk.extras.email import EmailProcessor, ProcessEmailContext  # noqa: PLC0415
        from soar_sdk.shims.phantom.vault import PhantomVault  # noqa: PLC0415

        email_text = UnicodeDammit(Path(file_info["path"]).read_bytes()).unicode_markup
        if not email_text:
            raise ValueError("Could not read email file contents from the vault")
        message = email.message_from_string(email_text)
        email_headers: dict[str, Any] = {}
        normalized: dict[str, str] = {}
        for key, value in message.items():
            existing = normalized.get(key.lower())
            if existing is None:
                normalized[key.lower()] = key
                email_headers[key] = value
            else:
                previous = email_headers[existing]
                email_headers[existing] = (
                    f"{previous}, {value}" if isinstance(previous, str) else previous
                )

        context = ProcessEmailContext(
            soar=soar,
            vault=PhantomVault(soar),
            app_id=app.appid,
            folder_name="parser",
            is_hex=False,
            action_name="extract ioc",
        )
        config = {
            "extract_attachments": True,
            "extract_domains": params.parse_domains,
            "extract_hashes": True,
            "extract_ips": True,
            "extract_urls": True,
            "run_automation": params.run_automation,
            "tags": tags,
        }
        processor = EmailProcessor(context, config)
        status, error, parsed_results = processor._int_process_email(
            email_text, params.vault_id, time.time()
        )
        if not status or not parsed_results:
            processor._del_tmp_dirs()
            raise ValueError(error or "Failed to process email")
        container = parsed_results[0].get("container") or {}
        if params.container_id is None:
            container.update({"label": params.label, "severity": severity})
            container_id = soar.container.create(container)
        else:
            container_id = params.container_id
        if processor._parse_results(parsed_results, container_id) is False:
            processor._del_tmp_dirs()
            raise ValueError("Failed to save processed email data")
        processor._del_tmp_dirs()
        artifacts_found = sum(
            len(result.get("artifacts", [])) for result in parsed_results
        )
        soar.set_summary(
            ExtractIocSummary(
                artifacts_found=artifacts_found,
                artifacts_ingested=artifacts_found,
                container_id=container_id,
            )
        )
        soar.set_message(
            f"Container id: {container_id}, Artifacts found: {artifacts_found}"
        )
        return ExtractIocOutput(**email_headers)

    context = ParserContext()
    result = ParseResult()
    if params.vault_id:
        if params.is_structured:
            status, parsed = parser_methods.parse_structured_file(result, file_info)
        else:
            status, parsed = parser_methods.parse_file(
                context, result, file_info, params.parse_domains, params.keep_raw
            )
    else:
        normalized_text = (params.text or "").replace(",", ", ")
        status, parsed = parser_methods.parse_text(
            context, result, params.file_type, normalized_text, params.parse_domains
        )
        file_info["name"] = "Parser Text"
    if not status or parsed is None:
        raise ValueError(result.message or "Failed to parse input")

    artifacts = parsed["artifacts"]
    if "before" in remap_mode:
        apply_remap(artifacts, parser_const.CEF2CIM_MAPPING)
        apply_remap(artifacts, custom_mapping)
    elif "after" in remap_mode:
        apply_remap(artifacts, custom_mapping)
        apply_remap(artifacts, parser_const.CEF2CIM_MAPPING)
    else:
        apply_remap(artifacts, custom_mapping)

    artifacts_found = len(artifacts)
    artifacts_to_save = (
        artifacts[: params.max_artifacts] if params.max_artifacts else artifacts
    )
    for artifact in artifacts_to_save:
        artifact.update(
            {
                "severity": severity,
                "tags": tags,
                "run_automation": params.run_automation,
            }
        )
    if params.container_id is None:
        container_id = soar.container.create(
            {
                "name": f"{file_info['name']} Parse Results",
                "label": params.label,
                "severity": severity,
                "artifacts": artifacts_to_save,
            }
        )
    else:
        container_id = params.container_id
        for artifact in artifacts_to_save:
            artifact["container_id"] = container_id
            soar.artifact.create(artifact)
    soar.set_summary(
        ExtractIocSummary(
            artifacts_found=artifacts_found,
            artifacts_ingested=len(artifacts_to_save),
            container_id=container_id,
        )
    )
    soar.set_message(
        f"Container id: {container_id}, Artifacts found: {artifacts_found}"
    )
    return ExtractIocOutput()


if __name__ == "__main__":
    app.cli()
