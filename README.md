[comment]: # "Auto-generated SOAR connector documentation"
# Parser

Publisher: Splunk  
Connector Version: 2\.5\.8
Product Vendor: Splunk  
Product Name: Parser  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

This app extracts IOCs from various files such as PDFs, emails, or raw text

[comment]: # " File: README.md"
[comment]: # "        Copyright (c) 2017-2022 Splunk Inc."
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


### Supported Actions  
[extract ioc](#action-extract-ioc) - Create IOC artifacts from a file in the vault or raw text  

## action: 'extract ioc'
Create IOC artifacts from a file in the vault or raw text

Type: **generic**  
Read only: **True**

Specify either text or vault\_id\. If text is used only file\_types of csv, html, and txt can be selected\. <br/><br/>If vault\_id is used and the \[file\_type\] is left blank, the app will try to determine what type of file it is on its own\. <br/><br/> When parsing an email file \(\.eml\), the <b>file\_type</b> parameter must be set to <b>email</b>\. <br/> <br/> <b>Label</b> or <b>Container ID</b> is mandatory to run an action\. It will display an error message if both of them are not mentioned\. <br/> <br/> <b> Caveats\:</b> <ul><li>If the \[file\_type\] you chose related to \[vault\_id\] is incorrect, you will have an unexpected output scenario\.</li></ul>

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  optional  | Vault ID | string |  `vault id` 
**file\_type** |  optional  | Type of the file | string | 
**text** |  optional  | Raw text from which to extract IOCs | string | 
**is\_structured** |  optional  | Use first row of CSV file as field names | boolean | 
**label** |  optional  | Add container to this label | string | 
**max\_artifacts** |  optional  | Maximum number of artifacts \(not applicable to \.eml filetype\) | numeric | 
**container\_id** |  optional  | Add created artifacts to this container | numeric | 
**remap\_cef\_fields** |  optional  | Remap the CEF fields with new field names; Optionally, also apply an internal CEF \-> CIM field name mapping\. Note\: \(source\|destination\)Address will be mapped to \(src\|dest\)\_ip respectively instead of src\|dest \(not applicable to \.eml filetype\) | string | 
**custom\_remap\_json** |  optional  | Custom set of CEF field name mappings\. This is a serialized json dictionary \(json\.dumps\) of Key/Value pairs where Key is an existing field name and Value is the resultant name \(not applicable to \.eml filetype\) | string | 
**run\_automation** |  optional  | Enable run\_automation for newly created artifacts | boolean | 
**severity** |  optional  | Severity for the newly created artifacts | string | 
**parse\_domains** |  optional  | Parse domains from artifacts | boolean | 
**artifact\_tags** |  optional  | Tags to add to artifacts \(comma separated\)\. Tag should only contain characters A\-Z, a\-z, 0\-9, \_, and \-\. Blank spaces will be ignored | string | 
**keep\_raw** |  optional  | Save raw text to artifact | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_id | numeric | 
action\_result\.parameter\.custom\_remap\_json | string | 
action\_result\.parameter\.file\_type | string | 
action\_result\.parameter\.is\_structured | boolean | 
action\_result\.parameter\.label | string | 
action\_result\.parameter\.max\_artifacts | numeric | 
action\_result\.parameter\.parse\_domains | boolean | 
action\_result\.parameter\.keep\_raw | boolean | 
action\_result\.parameter\.artifact\_tags | string | 
action\_result\.parameter\.remap\_cef\_fields | string | 
action\_result\.parameter\.run\_automation | boolean | 
action\_result\.parameter\.severity | string | 
action\_result\.parameter\.text | string | 
action\_result\.parameter\.vault\_id | string |  `vault id` 
action\_result\.data | string | 
action\_result\.summary\.artifacts\_ingested | numeric | 
action\_result\.summary\.artifacts\_found | numeric | 
action\_result\.summary\.container\_id | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.To | string | 
action\_result\.data\.\*\.Date | string | 
action\_result\.data\.\*\.From | string | 
action\_result\.data\.\*\.Subject | string | 
action\_result\.data\.\*\.Content\-Type | string | 
action\_result\.data\.\*\.X\-MS\-Has\-Attach | string | 
action\_result\.data\.\*\.Content\-Language | string | 
action\_result\.data\.\*\.Message\-ID | string | 
action\_result\.data\.\*\.MIME\-Version | string | 
action\_result\.data\.\*\.References | string | 
action\_result\.data\.\*\.In\-Reply\-To | string | 
action\_result\.data\.\*\.Thread\-Index | string | 
action\_result\.data\.\*\.Thread\-Topic | string | 
action\_result\.data\.\*\.X\-MS\-TNEF\-Correlator | string | 
action\_result\.data\.\*\.X\-MS\-Exchange\-Organization\-SCL | string | 
action\_result\.data\.\*\.X\-MS\-Exchange\-Organization\-RecordReviewCfmType | string | 