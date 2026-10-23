**Unreleased**

* Converted the Parser app to the Splunk SOAR SDK while preserving the `extract ioc` action.
* Preserved defaults for omitted optional inputs and email header names, casing, and repeated values.
* Fixed email IOC extraction and attachment ingestion, including artifact limits, tags, automation settings, and summary counts.
* Preserved the legacy email container deduplication key and made artifact persistence failures fail the action.
