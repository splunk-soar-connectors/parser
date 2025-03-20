This app will ignore the HTTP_PROXY and HTTPS_PROXY environment variables.

## URL Extraction

The app extracts defanged URL's that start with hxxp/hxxps. The defanged URL with [.] is not
considered valid. Therefore it does not get ingested. Hence, the app will not extract URLs defanged
with [.]
