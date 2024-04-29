[comment]: # "Auto-generated SOAR connector documentation"
# Parser

Publisher: Splunk  
Connector Version: 2.10.2  
Product Vendor: Splunk  
Product Name: Parser  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 5.5.0  

This app extracts IOCs from various files such as PDFs, emails, or raw text

[comment]: # " File: README.md"
[comment]: # "        Copyright (c) 2017-2024 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
This app will ignore the HTTP_PROXY and HTTPS_PROXY environment variables.  

## Defusedxml

This app uses the defusedxml module, which is licensed under the Python Software Foundation License
(PSFL), Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam, The Netherlands.



## URL Extraction

The app extracts defanged URL's that start with hxxp/hxxps. The defanged URL with \[.\] is not
considered valid. Therefore it does not get ingested. Hence, the app will not extract URLs defanged
with \[.\]




### Supported Actions  
[extract ioc](#action-extract-ioc) - Create IOC artifacts from a file in the vault or raw text  

## action: 'extract ioc'
Create IOC artifacts from a file in the vault or raw text

Type: **generic**  
Read only: **False**

Specify either text or vault_id. If text is used only file_types of csv, html, and txt can be selected. <br/><br/>If vault_id is used and the [file_type] is left blank, the app will try to determine what type of file it is on its own. <br/><br/> When parsing an email file (.eml), the <b>file_type</b> parameter must be set to <b>email</b>. <br/> <br/> <b>Label</b> or <b>Container ID</b> is mandatory to run an action. It will display an error message if both of them are not mentioned. <br/> <br/> <b> Caveats:</b> <ul><li>If the [file_type] you chose related to [vault_id] is incorrect, you will have an unexpected output scenario.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** |  optional  | Vault ID | string |  `vault id` 
**file_type** |  optional  | Type of the file | string | 
**text** |  optional  | Raw text from which to extract IOCs | string | 
**is_structured** |  optional  | Use first row of CSV file as field names | boolean | 
**label** |  optional  | Add container to this label | string | 
**max_artifacts** |  optional  | Maximum number of artifacts | numeric | 
**container_id** |  optional  | Add created artifacts to this container | numeric | 
**remap_cef_fields** |  optional  | Remap the CEF fields with new field names; Optionally, also apply an internal CEF -> CIM field name mapping. Note: (source|destination)Address will be mapped to (src|dest)_ip respectively instead of src|dest (not applicable to .eml filetype) | string | 
**custom_remap_json** |  optional  | Custom set of CEF field name mappings. This is a serialized json dictionary (json.dumps) of Key/Value pairs where Key is an existing field name and Value is the resultant name (not applicable to .eml filetype) | string | 
**run_automation** |  optional  | Enable run_automation for newly created artifacts | boolean | 
**severity** |  optional  | Severity for the newly created artifacts | string | 
**parse_domains** |  optional  | Parse domains from artifacts | boolean | 
**artifact_tags** |  optional  | Tags to add to artifacts (comma separated). Tag should only contain characters A-Z, a-z, 0-9, _, and -. Blank spaces will be ignored | string | 
**keep_raw** |  optional  | Save raw text to artifact | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success  failed 
action_result.parameter.artifact_tags | string |  |   tag1, tag2 
action_result.parameter.container_id | numeric |  |   1776 
action_result.parameter.custom_remap_json | string |  |   {"a": "fileHash", "b": "sourceAddress"} 
action_result.parameter.file_type | string |  |   txt  email  pdf  docx  csv  html 
action_result.parameter.is_structured | boolean |  |   True  False 
action_result.parameter.keep_raw | boolean |  |   True  False 
action_result.parameter.label | string |  |   Events 
action_result.parameter.max_artifacts | numeric |  |   100 
action_result.parameter.parse_domains | boolean |  |   True  False 
action_result.parameter.remap_cef_fields | string |  |   Apply custom remap and apply CEF -> CIM remapping after 
action_result.parameter.run_automation | boolean |  |   True  False 
action_result.parameter.severity | string |  |   low 
action_result.parameter.text | string |  |   Test string to extract IOCs from 
action_result.parameter.vault_id | string |  `vault id`  |   3d6ef06ab51be5a86cdfaba246db2c2ab1d07795 
action_result.data | string |  |  
action_result.data.\*.Content-Language | string |  |   en-US 
action_result.data.\*.Content-Type | string |  |   multipart/alternative; boundary="0000000000005233b405c7737dbe" 
action_result.data.\*.Date | string |  |   Mon, 19 Jul 2021 11:18:40 +0530 
action_result.data.\*.From | string |  |   xyz@xyz.com 
action_result.data.\*.In-Reply-To | string |  |   <CAGUkOuok3+qiuH4rCNKf=6_a4qwRViq=1WTro1pB8zSVqEujog@mail.gmail.com> 
action_result.data.\*.MIME-Version | string |  |   1.0 
action_result.data.\*.Message-ID | string |  |   <xyz@mail.gmail.com> 
action_result.data.\*.References | string |  |   <xyz@mail.gmail.com> 
action_result.data.\*.Subject | string |  |   =?UTF-8?B?5paw44GX44GESUTF-8?B?MeOBpOOCkuS9v+eUqOOBl+OBpuOAgeS4gOaEj+OBruODquODs+OCr+ODreODvOOCq+ODq+OCouODiQ==?=
	= 
action_result.data.\*.Thread-Index | string |  |   AQHWF83DD6R+qs4BTUSciZoeNB7NYw== 
action_result.data.\*.Thread-Topic | string |  |   
	=?utf-8?B?5ryi5a2XwqnCrMm40aDWjdue4KiK4K+14LWs4LyD4YCk4YSo4YeX4YqW4Y+M?=
 
action_result.data.\*.To | string |  |   xyz@xyz.com 
action_result.data.\*.X-MS-Exchange-Organization-RecordReviewCfmType | string |  |   0 
action_result.data.\*.X-MS-Exchange-Organization-SCL | string |  |   -1 
action_result.data.\*.X-MS-Has-Attach | string |  |   yes 
action_result.data.\*.X-MS-TNEF-Correlator | string |  |   xyz 
action_result.data.\*.Received | string |  |   from mansh7fre.z21h3fdhjbvjhjhjjgqechox4fh.zx.internal.cloudapp.net ([20.77.122.17])
        by smtp.test.com with ESMTPSA id t12-20020adff60c000000b002366ded5864sm7050556wrp.116.2022.10.31.06.25.08
        for <sgdsg@test.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 31 Oct 2022 06:25:08 -0700 (PDT) 
action_result.data.\*.X-Received | string |  |   by 2002:a05:600c:3585:b0:3b4:a308:1581 with SMTP id p5-2drfh78uy6sadtd003b4a3081581mr18516488wmq.77.1667222709252;
        Mon, 31 Oct 2022 06:25:09 -0700 (PDT) 
action_result.data.\*.Return-Path | string |  |   buhhjggj887@test.com 
action_result.data.\*.IronPort-SDR | string |  |   635fccb7_90V6GckKA2l9BvDxvI24Rhw29Af6jLnJvUY0wqFQaa+Pbol
 W1pRHLHUcEmR9erE+mHJJjbWp/GmDYT8uGz13ig== 
action_result.data.\*.Received-SPF | string |  |   None (mail6.hdds.com: no sender authenticity
  information available from domain of
  gvhjh@mail-wm1-f50.test.com) identity=helo;
  client-ip=209.85.128.50; receiver=mail6.gghjc.com;
  envelope-from="ysduj@ftdgc.com";
  x-sender="gvhjh@mail-wm1-f50.test.com";
  x-conformance=spf_only 
action_result.data.\*.X-Amp-Result | string |  |   UNKNOWN 
action_result.data.\*.IronPort-Data | string |  |   AgcvhadGfhgBsjdbnmsa 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 
action_result.data.\*.IronPort-PHdr | string |  |   QEslkmdkmd,sxcm:jkxsansam,xsmhjdds QEbwUCh8QSkl5oK+++Imq/EsTXaTcnF
 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 
action_result.data.\*.X-IPAS-Result | string |  |   gssahjdxsauijn=xs0HMUQDKy19jfzKAVdFaHAEBASsBAQcBAQEFAQEEBAEBA?=
 =?us-ascii?q?gEJAYFmGIErAgEBAWOBLCsuBFCET4t/hRtYgkCDLoRQBSsCUQkrBhqDIIENg?=
 =?us-ascii?q?VYCASoEB2kCA4JVgyktgmQTgSw9CAcBAQEBAQEBAQEEAQMBAhIBBSYEBAEBA?=
 =?us-ascii?q?wSEdSE5AQgGCYQTAh0HAUsBAgECAQEBAQEDAgMBAQEBAQEDAQEBBAEBAQIBA?=
 =?us-ascii?q?QIEAwEBAQIQAQEYCRkHDg4FJIVoDYF6HAwTInxNAzgBAQEBAQEBAQEBAQEBA?=
 =?us-ascii?q?QEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBBAJ+KAEhFhEdAQQXHgMSRwIEGAkRA?=
 =?us-ascii?q?QUBV4F8AV+CbAEDHxEDA5w1gX4BIIEEQopCcIEVBQIDE4EBggkGBQMCAYREC?=
 =?us-ascii?q?hkoDWuBUwcCBwkBCIEpAwEBAQGBT4ccgkiER3ongimBS4IyEoFzgwWBB4MKM?=
 =?us-ascii?q?oI0BItXXgmBMDggYG2FdwQPGQMDAiEDRB0CBAUDIwUKAwsJCBM/BgMBAQwHP?=
 =?us-ascii?q?QQEDA8HGAMBAQ8kAQECAgIDBAcCAQMGAwwCAgEBAQUGDQMCAwgTAwIBAwUCA?=
 =?us-ascii?q?gQBAgQKCAECAgECBAUGAQIBCAUBBQoDBQkFAgQBAQIDBwQDCwYCBQIBAgMFA?=
 =?us-ascii?q?QIDAgEKBQIDAQIBAQMGBAQBAQIDAgIBBgICAQEDAwQDAQIEAgICBwIDAgEEA?=
 =?us-ascii?q?gECAwEBAQICAgICAgMDCQIIBwUBAgQBAgEEAwICAQIHAQICAQgDAwUFAgcPA?=
 =?us-ascii?q?wUDAQMDAgUPAwEGBQECAQICAgIEAggCBAUCBQMCBAIDAgIIAwIDAQIBBwQDB?=
 =?us-ascii?q?AEEAgQDDwQDBAIDAgIFAgICAgIFAgIDAQICAgICAgUCAwIBBQECAgECAgIEA?=
 =?us-ascii?q?QICBwQCAwEDBA4EAwICBwECAgEGAgcDAQIBBAMBAQQCBAECBQIEAQMGAgMBA?=
 =?us-ascii?q?woCAgMCAQECAwMFAwMCCAgCAwUCBAEBAgQDBAICCwEGAgcCAgMCAgQEBAEBA?=
 =?us-ascii?q?gEEBQIDAQIDAwkCAgMCBAICCgEBAQECAQcCBAcGAgUCAgIDAQICAgEDAgIBA?=
 =?us-ascii?q?QICChIBAQIDAwMEBgUDAgMFAgEVAQYCAQECAgMDAgYCAQIIAgQBBAUCAQIBA?=
 =?us-ascii?q?QICBAEIAgIBAQECAQICAwMCAQICAgQDAgEBAgECAgIDAgICAwICAQ8CBgYBA?=
 =?us-ascii?q?gICAgICAgICBgECAQIDAQIHAgQDAgECAgUCAgIDAQEGAgQLAQMCAgICAQYBA?=
 =?us-ascii?q?wEBAgUBAgICAwEBAwMEAwMLAwIMCAEFAQMBIAMCAggCBwIBBgMCAQ8DAgIDA?=
 =?us-ascii?q?gIBBAoCAwUCBAIBBAkHAgQBAgkDAgYCBwUYAQICBwQMCgEBAgIFBgIEAQECA?=
 =?us-ascii?q?wECAQECAwQCAwIEBQEFAgECBQICAgIBAQIFAgwBAgEDBAIEAgcCAgICAwECA?=
 =?us-ascii?q?gIBAgEDAwIDAQEBAwYGAgMEBAIDAwYCAgIDAQICAwIEDQIBBQICBgMCBAENB?=
 =?us-ascii?q?QUEBQQDAggBAgEBBwIEAgcJDgIBAgQBBQICAwICAQUCAQIEAwECAgICBQgFA?=
 =?us-ascii?q?wQBBAMVAwEBBAMCAQIBBAMCAwcDAgQEAwECAwQGBgEJAwICBgMCAgEBDQMEA?=
 =?us-ascii?q?gIBAgECAwQEBAICAgIBAgICAgMEAgIBAQMDAwICAgMEAgMDCwYKAQcCAgIDA?=
 =?us-ascii?q?gEFCwICAgMCAQEDBgMBBQIEAgIGAQIEAgICAgICAgMBAQMKBAIBAgMCAgYDB?=
 =?us-ascii?q?gIBAgECAQkFAgEJAwECAQMEAQMJAQICBAkCAwcFBAYEAgICAggCAg4DAwIBA?=
 =?us-ascii?q?QQCAgQDAgICCwIBAgcCBQEBAwUHAgIBAgIBBAMBCQQBAgIDAgEBAwMRAwMDA?=
 =?us-ascii?q?QQCAgUDAw0JBgICAQMCAwENAwMBAgECAwEFBRcDAgEIBwMTAwIBAQMCAQICA?=
 =?us-ascii?q?wYNAgIDAwMCAQIFAgQDAwEFAgEBAwEFAwIOAwIDAwMCBgECAQECAwMBDAQCA?=
 =?us-ascii?q?wEBAQEXAQIDAgQCAgEBAgUBBAMBAQIBAgMCAg4GAQQFDAUCAQIfAgIDAwEEB?=
 =?us-ascii?q?QICAggCAgIBAwMBAwMFAQIDBAICAQUEBgQCAgICAgICAQwClAoCDCsIBxUdJ?=
 =?us-ascii?q?z8KKIMvUF8ZgR0LPXuBAwIBAZE6EwqDVYwuVZIEjFsPHgkBBgJbgVJ8FxsNB?=
 =?us-ascii?q?YYYhV6LI4dJUIEWM4NlARKMU4YhkieGXW+OaHenTAIKBwYQIxKBWwyBXHBXX?=
 =?us-ascii?q?QEBOFxtTwMZD443g1uKfiE0OwIHCwEBAwmJYF4BAQ?= 
action_result.data.\*.X-IronPort-AV | string |  |   E=Sophos;i="5.95,228,1661832000"; 
   d="pdf'?scan'208";a="17527695" 
action_result.data.\*.DKIM-Signature | string |  |   v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=test.com; s=20210112;
        h=mime-version:to:from:subject:date:message-id:from:to:cc:subject
         :date:message-id:reply-to;
        bh=G6MOWm8IxsWIXK+E9cSPXsZUV8kMF62PRajdB0itqYo=;
        b=EuhoEvKCqFlTYYCZBZBEzUzLfQ4+a9YkucvjR+RL4ZtJowjnLImqQfPVk3Jb3eEqAo
         yIRa4sJfs1y5VB21X14+d0KGiGd8ROfYkBmE3vLj5FmaOOKp5BHCQ7OOKfqwDlP/pxF3
         AY/NZgYxHCjdOOUPRbLoZNNdqgeCoQ7YT1Q3Qyb7qXr/OgNCVzvVGvdjlnsXOVsXtGE0
         ykWj6R8eQVp8zQ8snhFalrdP/aJstJa54e82bTb7rScJDoHIFwaLiTFtvDHEDEHV9Qd/
         airADFSq28tbda8KQBPKfuwSnAMCYSuDiOS/VLmJzkAwxKXbyArdS7sLhpVJFPEk7t5H
         lRSQ== 
action_result.data.\*.IronPort-HdrOrdr | string |  |   A9a23:9U7lNq8V4jTDmL7ZUA1uk+AFI+orL9Y04lQ7vn2ZLiYlF/Bw9v
 re/sjzuiWVtN98Yh8dcLO7V5VoKEm0naKdirNhXotKMjOGhEKYaK9v6of4yyDtFmnU5odmuZ
 tIQuxbBMfrBVZ3yeT38GCDeeoI8Z2i/LqzjenTi01xSxpnApsM0y5iBh2FHlZNSA5KOJo8GP
 OnjfZ6mw== 
action_result.data.\*.X-Gm-Message-State | string |  |   gjkwxWxdoK20dUSWBYLIn7gnobu5VoUCUYcraQo0EicpQQELl3HK5oG
	8wrn0qDdzJARTnQuR8t+qMQl5e6+8C3zQQ== 
action_result.data.\*.X-Amp-File-Uploaded | string |  |   False 
action_result.data.\*.X-Google-Smtp-Source | string |  |   owqkSWSM6EI96NBN6wZMoTHH0X9sNIiQ/A/Xfw/kDRMmNqDF8efL+kFhpOjB8CWsBjI8i34hcmAWD2yA== 
action_result.data.\*.Authentication-Results | string |  |   mail6.tgdd.com; spf=Pass smtp.mailfrom=ygdd@test.com; spf=None smtp.helo=dsds@mail-wm1-f50.test.com; dkim=pass (signature verified) header.i=@test.com; dmarc=pass (p=none dis=none) d=test.com 
action_result.data.\*.X-Amp-Original-Verdict | string |  |   FILE UNKNOWN 
action_result.data.\*.X-Google-DKIM-Signature | string |  |   v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=mime-version:to:from:subject:date:message-id:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=G6MOWm8IxsWIXK+E9cSPXsZUV8kMF62PRajdB0itqYo=;
        b=KZK25hKZcvCD6c/gBU7zzocEzqoOTNaAsayBZER10hTS6MU82iqd1mVo+YS137GuWT
         yju6NgH4nouHvnPHC/9+Ka4YtgUh+aMQiJJ9FqoYjkJ1CDFbMBdAxC71ATJxeK3yLYuT
         IsiDWAxufsz9oqoLwQBTzhm6To+4MbIGsdG5DJB4UM+Fojll7FRx/ChUo3aB7KIPW0pK
         1VtgeNpqDq4ou+I1ukiAnqhylWMWbubHd6s37PT8jC1yo00tO7DqR8+ArfXRy4jODfBH
         M4iXuvnBT5j4wO4UD/+y3wazJchEC/OcSSos2w0SYHRTlGYXEI7nYXXKwQH+4c4zz4L3
         sQRg== 
action_result.data.\*.X-IronPort-Anti-Spam-Filtered | string |  |   true 
action_result.data.\*.X-MS-Exchange-Organization-AuthAs | string |  |   Anonymous 
action_result.data.\*.X-MS-Exchange-Organization-AuthSource | string |  |   ILG1WNEX01.vcorp.ad.vrsn.com 
action_result.data.\*.X-MS-Exchange-Processed-By-BccFoldering | string |  |   15.01.2507.013 
action_result.data.\*.X-MS-Exchange-Transport-EndToEndLatency | string |  |   00:00:00.4499410 
action_result.data.\*.X-MS-Exchange-Organization-AVStamp-Enterprise | string |  |   1.0 
action_result.data.\*.X-MS-Exchange-Organization-Network-Message-Id | string |  |   cfc822d7-70b2-4fdf-a024-08dabb4356d5 
action_result.summary.artifacts_found | numeric |  |   13 
action_result.summary.artifacts_ingested | numeric |  |   1 
action_result.summary.container_id | numeric |  |   1776 
action_result.message | string |  |   Container id: 52069, Artifacts found: 27 
summary.total_objects | numeric |  |   2 
summary.total_objects_successful | numeric |  |   1 