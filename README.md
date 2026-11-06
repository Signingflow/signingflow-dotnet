# signingflow

[![CI](https://github.com/Signingflow/signingflow-dotnet/actions/workflows/ci.yml/badge.svg)](https://github.com/Signingflow/signingflow-dotnet/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/Signingflow/signingflow-dotnet/badges/coverage.json)](https://github.com/Signingflow/signingflow-dotnet/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

.NET SDK for the Signingflow calls used to send a document, read envelope status, and receive webhooks.

The package talks to `https://api.signingflow.com`. Keep the API key on your server. .NET 8 or newer is required. The SDK has no runtime dependencies.

```xml
<PackageReference Include="Signingflow" Version="0.1.0" />
```

The package id is `Signingflow`. The package is not on NuGet. Pack it from a checkout of [github.com/Signingflow/signingflow-dotnet](https://github.com/Signingflow/signingflow-dotnet):

```bash
dotnet pack -c Release -o ./nupkg
dotnet add package Signingflow --source ./nupkg
```

```csharp
using var signingflow = new SigningflowClient(
    Environment.GetEnvironmentVariable("SIGNINGFLOW_API_KEY"),
    ClientOptions.NewBuilder()
        .WorkspaceId(Environment.GetEnvironmentVariable("SIGNINGFLOW_WORKSPACE_ID"))
        .Env("sandbox")
        .Build());

Envelope envelope = await signingflow.Envelopes.SendDocumentAsync(
    "NDA",
    pdfBytes,
    path: null,
    "contract.pdf",
    [new Recipient("Ada Lovelace", "ada@example.com")],
    "Please sign");
```

`file` is a `byte[]`. `null` means no bytes. A zero-length array is an empty file. A disk path is `path`, and it is read only from `UploadRoot`. That directory must be one this process writes. The open refuses a symlink, a hard link, an absolute path, and a path that leaves the directory. On Windows, on a system whose `stat` layout is not macOS, Linux x64, or Linux arm64, or when `lstat` is not available, a path is refused and the file is not opened. Passing bytes in `file` does not need it. Do not pass a path from a request field.

`Env` is `sandbox` or `live`. The client always sends `X-Request-Env`. A missing environment header is treated as live by the API, so the client rejects a missing environment.

`BaseUrl` must be `https`. The host is `api.signingflow.com` unless `AllowCustomBaseUrl` is set. A username or password on the URL is rejected. The host comparison is case-sensitive. There is no process-wide API key. The client does not use `HTTPS_PROXY`.

The client sends `Accept-Encoding: identity`, does not follow redirects, and stops reading once an API response passes 8 MB. A response that ends before its declared length is not treated as the resource.

## Send and read

`Envelopes.PrepareDraftAsync` stores one PDF and creates a draft. It does not email anyone.

`Envelopes.SendDocumentAsync` stores the PDF, creates the draft, adds the recipients to the first document, and sends. `Envelopes.SendFromTemplateAsync` starts from `templates/{id}`.

If update or send fails, the error includes `EnvelopeName` for the draft that was saved. After a timeout, the client returns the envelope only when `SentTime` is within two minutes after the call started and not more than a minute ahead of this clock. An older or far-future timestamp is an error.

`Envelopes.ListAsync("needAction", null, null, null)` reads pages of 10. `pageSize` can be from 1 to 1000. Omitting it selects 10. `0` is rejected. `AllAsync` walks later pages and stops after 100 follow-up pages or a repeated token.

`Envelopes.DownloadCompletedAsync(name)` reads the envelope first. It requests the download URL only when the state is `COMPLETED`. The download call returns `Uri`, `DownloadTime`, and `Etag`. This client does not GET `Uri`. Treat that URL as untrusted until your application checks the host. Do not send the API key to it.

`Envelopes.RemindAsync(name)` notifies people who can still sign. The call is not idempotent.

## Idempotency

Creates and sends send a UUID `idempotencyKey` in the JSON body. The same key is stored for the whole environment. A repeat returns HTTP 409 and does not return the original resource. The SDK raises `SigningflowException.IdempotencyException` with `ResourceName` when the error includes one. It does not treat that response as success.

Pass the same idempotency key only to retry one request after a timeout. `UpdateAsync` and `RemindAsync` are not retried automatically. A query value that contains the API key is rejected, including when that key is percent-encoded.

## Webhooks

```csharp
WebhookUrl destination = await signingflow.WebhookUrls.CreateAsync(
    "Envelope events",
    "https://example.com/webhooks/signingflow",
    ["DOC_ENVELOPE_COMPLETED"],
    httpConfig: null,
    idempotencyKey: "");
string secret = WebhookUrls.SigningSecretOf(destination);
```

Store that secret from the create response. A later `RetrieveAsync` does not include it. Do not set `httpConfig`. `auth` `NONE` is rejected.

```csharp
Event constructed = Webhooks.ConstructEvent(rawBody, signatureHeader, secret, previousSecret, previousSignature);
constructed.Payload;
constructed.BodySha256;
```

`rawBody` is the exact request bytes. Store `BodySha256` with the event so a repeat delivery is recognizable. `previousSecret` is checked only together with `previousSignature`.

## Errors

| Exception | When |
| --- | --- |
| `AuthenticationException` | HTTP 401 |
| `PermissionException` | HTTP 403 |
| `IdempotencyException` | HTTP 409 whose body mentions idempotency |
| `RateLimitException` | HTTP 429 |
| `InvalidRequestException` | Other HTTP 4xx, and rejected arguments |
| `ApiException` | HTTP 5xx, or a body that is not JSON |
| `ConnectionException` | The API could not be reached, or the call timed out |
| `SignatureVerificationException` | A webhook signature did not match |

An API error does not keep an API key that contains a slash or a space, including when that key is percent-encoded in lowercase. `FieldViolations` lists field errors returned by the API.
