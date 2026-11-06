# Changelog

## 0.1.0

First .NET SDK for sending a document, reading envelope status, downloading a completed file, and verifying webhook signatures.

Pack it from a checkout with `dotnet pack -c Release` until the package is on NuGet. The package id is `Signingflow`.

The package is licensed under the Apache License 2.0. The API host is HTTPS `api.signingflow.com` unless a custom base URL is allowed. A file path is read only from `UploadRoot`, and only when the process can `lstat` the file and open it without following a link. That read is refused on Windows and on any system other than macOS, Linux x64, or Linux arm64. A hard link and an absolute path are rejected. Byte uploads do not need that. `ConstructEvent` returns `Payload` and `BodySha256` of the raw body. A 409 is an idempotency error only when the body says the key was already used. A timed-out send is returned only when `SentTime` falls in the two minutes after the call started. The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading an API response at 8 MB. A query value that contains the API key is rejected, including when that key is percent-encoded. An API error does not keep an API key that contains a slash or a space, including when that key is percent-encoded in lowercase. A response that ends before its declared length is not treated as the resource. The client does not send the API key through a proxy.
