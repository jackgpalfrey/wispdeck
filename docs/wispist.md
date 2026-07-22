# Wispist v1 design

Status: v1 implementation contract, 2026-07-13.

Wispist is a lightweight, browser-facing backend for simple websites. It gives
static HTML, CSS, and JavaScript persistent JSON data and live updates without
requiring the site author to deploy or configure an application server.

Wispdeck is the first host of Wispist, but Wispist is designed as an independent
technology. It lives in the Wispdeck repository and process initially without
depending on Wispdeck's users, domains, releases, or control-plane schema.

## 1. Product contract

For a site hosted by Wispdeck, Wispist is already present:

```js
const checklist = wispist.collection("before-you-go");

const items = await checklist.list();

const item = await checklist.add({
  text: "Buy travel insurance",
  done: false,
});

await checklist.update(item, { done: true });
```

There is no connection step, project identifier, endpoint, API key, or secret in
site code. The host derives the correct data namespace and policy from the HTTP
request. The client performs no network or background work until the site first
uses it.

The same client remains usable outside Wispdeck with one explicit script:

```html
<script src="/_wispist/client/v1.js"></script>
```

An explicitly remote client may be added later. It is not part of v1.

### 1.1 Design principles

1. **A backend that is simply there.** The common path has no setup code.
2. **Static-site first.** Every feature must be usable from plain browser
   JavaScript without a build step or an application server.
3. **No idle compute.** An unused namespace has bytes on disk but no dedicated
   process, goroutine, timer, poller, or database connection.
4. **Default deny.** A site must explicitly declare every accessible collection
   and its access policy.
5. **Server-enforced authority.** Client configuration is public and is never a
   security boundary.
6. **Safe concurrency.** Mutations never silently overwrite a revision the
   caller did not observe.
7. **Bounded operation.** Documents, collections, storage, requests,
   subscriptions, and change history all have explicit limits.
8. **Portable core.** Wispist accepts opaque namespaces and principals; it does
   not contain Wispdeck concepts.
9. **Small before clever.** V1 has document CRUD and subscriptions, not a query
   language, arbitrary functions, or a Firebase-compatible surface.

### 1.2 V1 goals

- JSON document collections.
- Individual-document atomicity and optimistic concurrency.
- A dependency-free browser client exposed automatically by Wispdeck.
- Collection subscriptions over Server-Sent Events (SSE).
- Declarative per-collection access.
- Strict live/draft data isolation.
- A SQLite persistence implementation with no per-site idle work.
- Stable, versioned HTTP and JavaScript contracts.
- Host interfaces that can accept Wispdeck identity or a future Wispist identity
  system without changing the data engine.

### 1.3 V1 non-goals

- Arbitrary SQL or exposing SQLite.
- Joins, server-side filters, secondary indexes, or a query language.
- Multi-document transactions or batches.
- Offline-first synchronization or conflict-free replicated data types.
- User authentication supplied by Wispist.
- File/blob uploads.
- Serverless functions, scheduled jobs, triggers, or arbitrary server code.
- Cross-origin browser access.
- Multiple active Wispdeck nodes sharing one Wispist store.
- Automatic promotion of draft data into live data.

## 2. System boundary

Wispist is an in-process Go library. Wispdeck constructs one engine at startup
and calls it from the hosted-site request path; there is no second application,
IPC boundary, or Wispdeck-specific wrapper around the engine.

The runtime shape is:

```text
Browser
  |
  | Wispist HTTP v1 + SSE
  v
Wispdeck hosted-site boundary
  |  resolves a generic wispist.Binding
  v
*wispist.Engine
  |  protocol, policy, documents, revisions, changes, and client
  v
Configured Wispist store implementation
```

The dependency direction is one way: Wispdeck imports and instantiates Wispist;
Wispist must not import Wispdeck.

Conceptually, composition looks like:

```go
engine, err := wispist.NewEngine(wispist.Config{
    StoreFactory: storeFactory,
    Authorizer:   authorizer,
    Limits:       limits,
    RateLimits:   rateLimits,
    Logger:       logger,
})
```

For each hosted-site request, Wispdeck resolves its own concepts and supplies
only generic Wispist values:

```go
binding := wispist.Binding{
    StoreKey:  storeKey,
    Namespace: namespace,
    Origin:    origin,
    ClientKey: clientKey,
    Principal: principal,
    Declaration: releaseDeclaration,
    Mode:      wispist.ModeLive,
    ReadOnly:  false,
}

engine.ServeHTTP(w, r, binding)
```

The exact Go field types are implementation details, but this ownership and call
direction are part of the design. Following Go naming conventions, the exported
type is `wispist.Engine`; “Wispist Engine” is the technology-level name.

The intended repository shape is:

```text
wispist/
    engine.go       configured Engine and public host-facing contract
    types.go        generic bindings, principals, policy, and store contracts
    declaration.go strict release-declaration parsing
    http.go         HTTP resources and conditional document operations
    sse.go          retained-change and live subscription protocol
    sqlite/         SQLite store implementation and contract tests
    client/         dependency-free browser client source

docs/wispist.md
```

This remains one Go module initially. A nested module would make repository-wide
testing and dependency management harder without creating a stronger boundary.
An architecture test must instead fail if a package beneath `wispist/` imports
anything beneath `internal/`. Wispdeck's ordinary composition and hosted-site
code may import `wispist` directly; a parallel integration package is not
required.

There is no standalone `wispist` binary in v1. The engine, protocol handler,
store, and conformance tests must nevertheless be usable without constructing a
Wispdeck server. A later standalone binary should be assembly work rather than a
rewrite.

### 2.1 Responsibilities

Wispist owns:

- Collection and document validation.
- Document revisions and conditional mutations.
- Change sequencing and subscription semantics.
- Policy evaluation.
- Storage transactions.
- Protocol versioning and error responses.
- Generic quotas supplied through a namespace binding.

Wispdeck owns:

- Constructing the Wispist Engine with installation configuration.
- Determining which site an origin belongs to.
- Determining whether a request addresses live or draft data.
- Authorizing access to a private preview origin.
- Loading the Wispist declaration associated with a release.
- Constructing the request's `wispist.Binding`, including its opaque namespace,
  principal, release policy, mode, client key, and host restrictions.
- Choosing storage locations and installation-wide limits.
- Management UI, backups, data deletion, and operator observability.
- Applying an unconditional read-only restriction to a current-release preview.

## 3. Embedding and origin model

### 3.1 Reserved paths

Wispist reserves the complete `/_wispist/` prefix on a hosted-site origin.
Uploaded site files are never served from that prefix.

The v1 routes are:

```text
GET    /_wispist/client/v1.js
GET    /_wispist/v1
GET    /_wispist/v1/collections/{collection}/documents
POST   /_wispist/v1/collections/{collection}/documents
GET    /_wispist/v1/collections/{collection}/documents/{document}
PUT    /_wispist/v1/collections/{collection}/documents/{document}
DELETE /_wispist/v1/collections/{collection}/documents/{document}
GET    /_wispist/v1/changes
```

The prefix is independent of Wispdeck. Wispdeck-specific preview controls remain
beneath `/_wispdeck/`.

### 3.2 Automatic client availability

Wispdeck asks the configured Wispist Engine to transform served HTML documents.
The engine deterministically inserts a bootstrap as the first element of
`<head>`. The per-request binding supplies non-authoritative environment metadata
as attributes:

```html
<script
  src="/_wispist/client/v1.js"
  data-wispist-bootstrap
  data-wispist-mode="live"
  data-wispist-read-only="false"
></script>
```

If an HTML document has no `head`, Wispdeck inserts a valid `head`. Injection is
performed with an HTML tokenizer, not a case-sensitive byte search. The script
is deliberately parser-blocking so `globalThis.wispist` exists for every later
site script. It makes no API request during evaluation.

The transformation has these HTTP consequences:

- The public representation's ETag and Content-Length describe the transformed
  bytes.
- `GET`, `HEAD`, conditional requests, and byte ranges operate on the same
  transformed representation.
- Preview-toolbar insertion happens in the same transformation pipeline.
- Non-HTML files are never transformed.
- The injected tag is not duplicated if an identical bootstrap tag is already
  the first element in `head`. A later or non-canonical lookalike cannot
  suppress the authoritative leading bootstrap.

`wispist` is a reserved global on Wispdeck-hosted sites. The bootstrap defines a
single non-enumerable, non-writable property on `globalThis`. It does not add
other globals. The attributes make `wispist.mode` and `wispist.readOnly`
available synchronously; the server still enforces both values independently.

The platform bootstrap executes before a document-level `meta` Content Security
Policy. That policy controls subsequent site resources and network operations. A
site with `connect-src 'none'` cannot use Wispist until it permits same-origin
connections. A response-header Content Security Policy, if Wispdeck later lets a
site configure one, must have an explicit documented allowance for the platform
bootstrap.

### 3.3 Same-origin by default

The embedded API is same-origin and emits no CORS permission. There are no
browser-visible API keys. Unsafe requests require an exact same-origin `Origin`
header and acceptable Fetch Metadata when the browser supplies it.

Cross-origin operation is intentionally deferred. It will require an explicit
allowed-origin model and must not change the embedded same-origin defaults.

## 4. Resource model

### 4.1 Namespace

A namespace is an opaque, host-provided identifier. It is the highest isolation
boundary visible to the Wispist engine. The engine must not infer meaning from
its contents.

Wispdeck uses a stable site identifier, not a user-selected hostname, to choose
the underlying database. Renaming or republishing a site therefore does not
move or merge its data.

Wispdeck supplies separate namespace keys for live and draft data when it builds
the request binding. Their exact encoding is private to Wispdeck.

### 4.2 Collection

A collection is an ordered set of JSON documents. A collection exists for API
purposes only when it is declared by the active release configuration. Removing
a declaration makes stored data inaccessible but does not delete it.

Collection names:

- Contain 1 to 48 bytes.
- Start with a lowercase ASCII letter.
- Continue with lowercase letters, digits, hyphens, or underscores.
- Are compared byte-for-byte and are not Unicode-normalized.
- Must not begin with `_`.

The grammar is:

```text
[a-z][a-z0-9_-]{0,47}
```

### 4.3 Document

A document consists of server-owned metadata and a caller-owned JSON object:

```json
{
  "id": "01k4example",
  "revision": "opaque-revision-token",
  "createdAt": "2026-07-13T12:34:56.123Z",
  "updatedAt": "2026-07-13T12:35:04.456Z",
  "data": {
    "text": "Buy travel insurance",
    "done": false
  }
}
```

`data` must be a JSON object. Scalars, arrays, and `null` are rejected as the
document root. Nested values may use every JSON type, including `null`.

JSON validation rejects:

- Invalid UTF-8.
- Duplicate object member names.
- More than 32 levels of nesting.
- Property names longer than 256 UTF-8 bytes.
- A representation exceeding the configured document-byte limit.

Wispist stores a normalized compact JSON representation but does not reorder
object keys. Clients must treat object-member ordering as insignificant.

Document IDs:

- Contain 1 to 64 ASCII characters from letters, digits, `_`, and `-`.
- Must not be `.` or `..`.
- Are case-sensitive.
- May be selected by the caller for deterministic records.
- Otherwise are generated by the server from at least 128 bits of randomness.

Timestamps are server-generated UTC RFC 3339 timestamps with millisecond
precision. They are informational, not concurrency tokens or ordering keys.

### 4.4 Revision

Every successful create or replacement produces a new opaque revision. A
revision is unique for that incarnation of that document. Delete and later
recreate never reuse a revision.

The HTTP ETag of a document is its quoted revision. Clients must not parse the
revision or assume it is numeric.

All replacement and deletion operations are conditional:

- Create at a caller-selected ID uses `If-None-Match: *`.
- Replace uses `If-Match: "<observed revision>"`.
- Delete uses `If-Match: "<observed revision>"`.
- Omitting the required precondition returns `428 Precondition Required`.
- A stale precondition returns `412 Precondition Failed`.

There are no unconditional last-write-wins mutations in v1.

### 4.5 Change sequence

Each namespace has a monotonically increasing 64-bit change sequence. A
successful document create, replacement, or deletion appends one change in the
same transaction as the document mutation.

Sequence values are implementation details exposed only as opaque cursor
strings. Clients must not do arithmetic on them.

## 5. Release declaration and access policy

### 5.1 `wispist.json`

A site release opts collections into browser access using `wispist.json` at the
archive root. The common shared-state case is intentionally short:

```json
{
  "version": 1,
  "collections": {
    "before-you-go": {
      "access": "shared",
      "limits": {
        "maxDocuments": 250,
        "maxDocumentBytes": 4096
      }
    }
  }
}
```

The declaration contains policy, not secrets. It is validated during upload.
Invalid configuration rejects the release; it never causes a permissive runtime
fallback.

V1 parsing is strict:

- The file must be valid UTF-8 JSON no larger than 64 KiB.
- Duplicate JSON keys are rejected.
- Unknown fields and unsupported versions are rejected.
- At most 32 collections may be declared.
- Every operation must be stated explicitly unless a defined access profile is
  used.
- Requested limits may only lower the host defaults.
- Missing `wispist.json` is equivalent to zero declared collections.

`wispist.json` is immutable with its release. Uploading a draft validates and
activates its declaration only for the draft view. Publishing or rolling back a
release atomically changes the live declaration to the declaration carried by
that release. It does not mutate documents.

### 5.2 Built-in access profile and policy values

The `"shared"` access profile expands to `"anyone"` for `list`, `read`,
`create`, `update`, `delete`, and `subscribe`. Its name is deliberately candid:
every visitor can see and change the collection.

More selective collections use the expanded form:

```json
{
  "access": {
    "list": "anyone",
    "read": "anyone",
    "create": "nobody",
    "update": "nobody",
    "delete": "nobody",
    "subscribe": "anyone"
  }
}
```

The v1 declarative policy accepts:

- `"anyone"`: allow the operation for any principal.
- `"authenticated"`: allow a principal asserted as authenticated by the host.
- `"nobody"`: deny the operation.

Wispdeck initially supplies anonymous principals to ordinary public and preview
site code, so `authenticated` is reserved for host integrations and future
identity work. Preview access proves permission to view a preview; it does not
silently grant the previewed JavaScript elevated data authority.

There is no implicit relationship between `read` and `list`, or between `read`
and `subscribe`. This prevents a declaration intended to expose one known
document from accidentally exposing a whole collection or its live stream.

A public shared checklist deliberately uses `anyone` writes. That means every
viewer can alter it. Origin checks, quotas, and rate limits reduce accidental and
automated abuse but do not turn public write access into user authorization.

### 5.3 Authorizer interface

The engine evaluates every operation through an authorizer. Its conceptual input
is:

```text
principal
namespace
operation: list | read | create | update | delete | subscribe
collection
document ID, if present
current document, if present
proposed document, if present
request metadata supplied by the host
```

Its output is allow or deny plus a stable reason code for internal metrics. The
browser receives only the public protocol error.

The interface intentionally includes current and proposed documents so a future
rules engine can make Firebase-like field and membership decisions. V1 does not
define a rules language.

The host may apply an overriding restriction, such as read-only preview mode,
which the collection policy cannot relax.

## 6. Wispdeck environment semantics

Wispist data is site-scoped and long-lived, not release-scoped. Releases select
code and policy; they do not each receive a new production database.

Wispdeck maps requests as follows:

| Request context | Release declaration | Data namespace | Mutations |
| --- | --- | --- | --- |
| Public published-site origin | Published release | Live | Per policy |
| Public origin with no published release | None | None | Denied |
| Preview origin, Draft selected | Current draft release | Draft | Per policy |
| Preview origin, Current selected | Published release | Live | Always denied |

The draft namespace is stable across successive draft uploads for the same site.
This lets test data survive ordinary iteration. A future management action may
reset draft data or explicitly copy live data into draft.

Publishing code never promotes draft data. In particular:

- Publishing a first release begins with empty live data unless live data was
  already created through an explicit management operation.
- Republishing preserves existing live data.
- Rolling back code preserves existing live data.
- Removing a collection declaration hides but does not delete its documents.
- Re-adding the collection makes those documents accessible again.

Data copying or promotion is necessarily explicit because test data may contain
destructive, private, or nonsensical values. It is outside v1.

The Current view on a preview origin reads live data but is forcibly read-only.
This makes it useful for comparing current code and state without allowing a
private preview session to mutate production accidentally.

## 7. HTTP protocol

### 7.1 General rules

- All API responses use `Cache-Control: no-store`.
- JSON responses use `Content-Type: application/json; charset=utf-8`.
- JSON request bodies require `Content-Type: application/json`.
- Request bodies are limited before decoding.
- Unknown JSON fields are rejected where the protocol defines an envelope.
- All responses include `X-Request-ID`; a caller-provided UUID may be retained,
  otherwise Wispist creates a UUID. Error responses use the same UUID in their
  Problem Details `instance` URI.
- Methods not supported by a known resource return `405` with `Allow`.
- API paths use decoded, canonical path segments. Encoded slashes, invalid UTF-8,
  dot segments, empty identifiers, and non-canonical escapes are rejected.
- HTTP dates and ETags follow normal HTTP syntax. Revisions remain opaque.

### 7.2 Service description

```http
GET /_wispist/v1
```

Returns protocol identity and limits visible to this request. It does not expose
other namespaces or operator details.

```json
{
  "name": "Wispist",
  "version": 1,
  "mode": "live",
  "readOnly": false,
  "collections": ["before-you-go"]
}
```

The `mode` values are `live`, `draft`, and `live-preview`. The value is
informational; enforcement remains server-side.

### 7.3 List documents

```http
GET /_wispist/v1/collections/{collection}/documents?limit=100&after={cursor}
```

Successful response:

```json
{
  "documents": [
    {
      "id": "insurance",
      "revision": "opaque",
      "createdAt": "2026-07-13T12:34:56.123Z",
      "updatedAt": "2026-07-13T12:34:56.123Z",
      "data": { "text": "Buy travel insurance", "done": false }
    }
  ],
  "after": null,
  "changes": "opaque-change-cursor"
}
```

Documents are ordered by creation sequence and then ID. `limit` defaults to 100
and is capped at 250. `after` is an opaque pagination cursor.

Pagination is not a frozen database snapshot. The `changes` cursor is captured
at the start of the first page and is repeated by subsequent pages. A client
that requires a live-consistent collection lists all pages and then consumes
changes after that cursor; this reconciles mutations that raced pagination.

### 7.4 Create with a generated ID

```http
POST /_wispist/v1/collections/{collection}/documents
Idempotency-Key: 128-bit-or-stronger-random-value
Content-Type: application/json

{"data":{"text":"Buy travel insurance","done":false}}
```

Returns `201 Created`, a `Location` header, a document ETag, and the complete
document envelope.

`Idempotency-Key` is required for POST. The key grammar is 16 to 128 visible
ASCII characters. For a given namespace, the same key and request fingerprint
returns the original response for at least 24 hours. Reusing a key with a
different request returns `409 Conflict`.

The JavaScript client generates the key automatically.

### 7.5 Read a document

```http
GET /_wispist/v1/collections/{collection}/documents/{document}
```

Returns the envelope and ETag, or `404 Not Found`. Conditional GET with
`If-None-Match` is supported even though the response is not stored in browser
caches by default.

### 7.6 Create or replace at a selected ID

Create:

```http
PUT /_wispist/v1/collections/{collection}/documents/{document}
If-None-Match: *
Content-Type: application/json

{"data":{"text":"Pack passport","done":false}}
```

Replace:

```http
PUT /_wispist/v1/collections/{collection}/documents/{document}
If-Match: "observed-revision"
Content-Type: application/json

{"data":{"text":"Pack passport","done":true}}
```

Create returns `201`; replacement returns `200`. Both return the complete new
document and ETag.

V1 deliberately uses whole-document replacement rather than JSON Merge Patch,
whose `null` behavior is surprising, or JSON Patch, which is unnecessarily
complex for the first use cases. The JavaScript client's `update` helper merges
fields locally and performs a conditional replacement.

### 7.7 Delete

```http
DELETE /_wispist/v1/collections/{collection}/documents/{document}
If-Match: "observed-revision"
```

Returns `204 No Content`. The deletion produces a change entry containing the
document ID and deleted revision, but no document body.

### 7.8 Changes and SSE

```http
GET /_wispist/v1/changes?collections=before-you-go&after={cursor}
Accept: text/event-stream
```

`collections` may be repeated and is capped at 8 values. Each collection must
permit `subscribe`, and every delivered document must also permit `read`.

Events use the form:

```text
id: opaque-change-cursor
event: change
data: {"collection":"before-you-go","operation":"update","document":{...}}

```

A deletion uses:

```text
id: opaque-change-cursor
event: change
data: {"collection":"before-you-go","operation":"delete","id":"insurance","revision":"opaque"}

```

The server sends a comment heartbeat no less often than every 25 seconds while
the connection is otherwise idle. Heartbeats carry no application state.

On connection, the handler:

1. Registers a bounded in-memory listener before reading the backlog.
2. Reads retained changes after the supplied cursor.
3. Sends the backlog in sequence order.
4. De-duplicates and sends any events queued during the backlog read.
5. Continues with newly committed events.

This prevents the read/subscribe race without polling. Mutations commit to
SQLite before they are published to in-memory listeners.

If the cursor is absent, the stream starts after the current high-water mark; it
does not replay the entire collection. If the cursor is older than retained
history, the server sends a `reset` event and closes. The client must list again.

Each stream has a bounded outgoing queue. A slow consumer receives `reset` and
is disconnected rather than consuming unbounded memory. Disconnect and
reconnect are normal. Delivery is at least once, so clients de-duplicate by
cursor.

An SSE connection is active compute and is expected only while a site is being
viewed. There is no listener or poller for an idle namespace.

## 8. Browser client

The global API is deliberately small:

```text
wispist.version
wispist.mode
wispist.readOnly
wispist.collection(name)
```

`mode` and `readOnly` are populated synchronously from server-authored bootstrap
attributes. They must not be used as security decisions.

A collection exposes:

```text
collection.list(options?)
collection.get(id)
collection.add(data)
collection.create(id, data)
collection.replace(document, data)
collection.update(document, changes)
collection.delete(document)
collection.subscribe(callback, options?)
```

All mutation methods return the resulting document except `delete`, which
resolves with no value.

`replace`, `update`, and `delete` accept an observed document envelope, not only
an ID. This makes safe concurrency the easiest path:

```js
const item = await checklist.get("insurance");

try {
  const updated = await checklist.update(item, { done: true });
} catch (error) {
  if (error.code === "revision_conflict") {
    // Refetch or tell the viewer that somebody else changed it.
  }
}
```

`update` performs a shallow merge of `document.data` and `changes`. A property
whose new value is `undefined` is omitted from the outgoing JSON but is not
deleted. Sites requiring deletion or nested changes construct a new object and
use `replace`.

`subscribe(callback)` is the ergonomic live-collection operation. It:

1. Lists all pages of the collection.
2. Opens the change stream from the list cursor.
3. Maintains an in-memory map by document ID.
4. Calls `callback(documents, event)` once for the initial state and after each
   applied change.
5. Reconnects with bounded exponential backoff and jitter.
6. Relists after `reset`.

It returns an unsubscribe function immediately:

```js
const unsubscribe = checklist.subscribe((documents, event) => {
  render(documents);
});

// Later:
unsubscribe();
```

Initial or terminal errors are reported through `options.onError`. Recoverable
disconnects do not produce noisy unhandled promise rejections.

The client uses `fetch`, `EventSource`, `AbortController`, and Web Crypto only.
It has no dependencies, does not use local storage, does not register a service
worker, and performs no analytics or telemetry.

### 8.1 Error type

Rejected operations throw `WispistError` with:

```text
name       "WispistError"
type       RFC 9457 problem-type URI
code       ergonomic code mapped from a known Wispist problem type
title      stable title for the problem type
detail     safe description of this occurrence
status     HTTP status, when available
instance   occurrence URI, when available
requestId  UUID from X-Request-ID, when available
problem    complete decoded Problem Details object
```

The wire representation does not contain a separate `code`; RFC 9457's `type`
URI is the primary machine identifier. `code` is a JavaScript convenience mapped
by the client, for example `revision_conflict` for the
`.../revision-conflict/` type. The client never derives behavior from `title` or
`detail`.

Network failures use `code = "network_error"` and have no problem type or HTTP
status.

## 9. Error protocol

API errors use RFC 9457 Problem Details and the
`application/problem+json` media type. RFC 9457's members are emitted as the
top-level object rather than beneath a Wispist-specific wrapper:

```json
{
  "type": "https://learn.peios.org/wispist/problems/revision-conflict/",
  "title": "Revision conflict",
  "status": 412,
  "detail": "The document changed after it was read.",
  "instance": "urn:uuid:019c0000-0000-7000-8000-000000000000"
}
```

The permanent type-URI root is:

```text
https://learn.peios.org/wispist/problems/
```

These URIs are protocol identifiers, not deployment URLs. Every type URI
resolves to human-readable documentation. They remain unchanged if Wispist or
its documentation is later hosted elsewhere; an old documentation origin may
redirect but the protocol continues to emit the original identifier.

`title` is stable for a problem type. `detail` describes only this occurrence.
`status` agrees with the actual HTTP status. `instance` is a `urn:uuid:` URI
formed from the same UUID returned in `X-Request-ID`.

Request-validation problems may add an `errors` extension:

```json
{
  "type": "https://learn.peios.org/wispist/problems/invalid-request/",
  "title": "Invalid request",
  "status": 400,
  "detail": "One or more request values are invalid.",
  "instance": "urn:uuid:019c0000-0000-7000-8000-000000000000",
  "errors": [
    {
      "pointer": "#/data/text",
      "detail": "must be a string"
    }
  ]
}
```

Each `pointer` is a URI-fragment JSON Pointer into the request representation.
Extensions are defined per problem type; implementations do not attach arbitrary
debugging maps.

V1 defines:

| HTTP | Type suffix | JavaScript code | Meaning |
| --- | --- | --- | --- |
| 400 | `invalid-request/` | `invalid_request` | Invalid path, query, envelope, or identifier |
| 400 | `invalid-json/` | `invalid_json` | Malformed or disallowed JSON |
| 401 | `authentication-required/` | `authentication_required` | Policy requires an authenticated principal |
| 403 | `forbidden/` | `forbidden` | Principal may not perform the operation |
| 404 | `not-found/` | `not_found` | Resource or declared collection is unavailable |
| 405 | `method-not-allowed/` | `method_not_allowed` | A known resource does not support the method |
| 409 | `idempotency-conflict/` | `idempotency_conflict` | Key was reused for another POST |
| 409 | `quota-exceeded/` | `quota_exceeded` | A namespace or collection limit would be exceeded |
| 412 | `revision-conflict/` | `revision_conflict` | Conditional revision did not match |
| 413 | `request-too-large/` | `request_too_large` | Body or document exceeds its byte limit |
| 415 | `unsupported-media-type/` | `unsupported_media_type` | Request is not JSON where JSON is required |
| 428 | `precondition-required/` | `precondition_required` | Safe mutation precondition was omitted |
| 429 | `rate-limited/` | `rate_limited` | Request rate exceeded a bounded allowance |
| 503 | `temporarily-unavailable/` | `temporarily_unavailable` | Store is busy or temporarily unavailable |

HTTP headers retain their normal authority. `Retry-After`, `ETag`, and
`WWW-Authenticate` are not replaced by Problem Details members. The client may
expose their useful values alongside the decoded problem.

Internal errors never return SQL, filesystem paths, policy internals, document
contents, stack traces, Go error strings, or sensitive policy predicates.

## 10. Persistence

### 10.1 Store abstraction

The engine depends on a store interface expressed in Wispist types. The store
must provide:

- Conditional single-document create, replace, and delete.
- Ordered list pagination.
- Transactional document mutation plus change append.
- Change reads after a cursor.
- Idempotency-key lookup and result recording.
- Namespace usage accounting.
- Conformance under concurrent callers.

Policy evaluation happens before storage, but the storage precondition and quota
checks happen inside the mutation transaction. A policy decision never replaces
the transactional recheck.

### 10.2 Wispdeck SQLite layout

Wispist data does not live in Wispdeck's control database. Wispdeck stores one
SQLite file per stable site ID beneath an operator-configured Wispist data
directory:

```text
data/
  wispdeck.db
  wispist/
    0123456789abcdef0123456789abcdef.db
```

The filename is derived only from a validated internal ID, never a hostname or
other user-controlled path. Files and directories are owner-only.

One site file contains both its live and draft namespaces. This gives a site a
clear backup, restore, quota, corruption, and deletion boundary without opening
one database per collection.

Reads of an untouched namespace return an empty result without creating a file.
The first mutation creates and migrates the file atomically.

SQLite uses:

- Foreign keys.
- WAL mode.
- A busy timeout.
- Strict tables where supported.
- A bounded number of connections.
- Transactions for every mutation/change/idempotency operation.
- Schema versioning independent of Wispdeck's control-plane schema.

The process maintains one bounded least-recently-used cache of open site stores.
Idle entries are closed. There is no cache, connection, timer, or goroutine per
site when it is not in use.

### 10.3 Change retention and cleanup

Default retained history is bounded by both limits: no more than 10,000 changes
per namespace and no change older than seven days. Crossing either boundary may
expire a cursor and require a relist. The host may lower these bounds within
implementation-supported limits.

Cleanup runs opportunistically during writes and installation-wide bounded
maintenance; it does not create a per-site timer.

Idempotency records are retained for at least 24 hours and cleaned by the same
bounded mechanism. A namespace has a separate default hard limit of 10,000 live
idempotency records. If that limit is reached, a new POST is rejected until
records expire; Wispist never breaks an existing key's retention promise to make
space.

### 10.4 Single-node constraint

V1 supports one active Wispdeck process for a data directory. SQLite remains the
durable source of truth, while live notification uses an in-process hub. A future
distributed store must provide a cross-node notification mechanism and pass the
same conformance suite.

### 10.5 Host management contract

The Engine exposes a host-facing administration surface in Go; it is not an
additional browser HTTP API. A host supplies a `wispist.NamespaceRef` containing
its opaque store key, namespace, and optional lower byte ceiling. The Engine
supports:

- Logical namespace and per-collection usage.
- Paginated document inspection.
- A consistent single- or multi-namespace snapshot for export.
- Revision-conditional document replacement and deletion.
- Collection clearing with one retained delete change per document.
- Hard namespace purge.

Management replacement uses the same strict JSON-object validation,
transactional quota checks, revision tokens, and post-commit live notification
as a site mutation. Clearing a collection is visible to subscribers through
ordinary delete changes. Hard purge instead removes documents, idempotency
records, retained changes, and the namespace sequence, then resets active
streams with `namespace_purged`; clients must relist from an empty cursor.

The embedding host owns authentication and authorization for this surface.
Wispist does not infer that a caller is a site owner, and Wispdeck never mounts
these methods on a content origin. This keeps the library independent while
allowing Wispdeck to provide an owner/superuser data console.

## 11. Limits and abuse controls

Initial host defaults:

| Resource | Default |
| --- | ---: |
| Declared collections per release | 32 |
| Documents per collection | 1,000 |
| Document JSON | 32 KiB |
| Live data per site | 10 MiB |
| Draft data per site | 5 MiB |
| List page size | 100, maximum 250 |
| Subscribed collections per SSE connection | 8 |
| SSE connections per browser address and site | 6 |
| Pending events per SSE connection | 128 |
| JSON request body | document limit plus 4 KiB envelope allowance |

The declaration may reduce collection-specific document counts and sizes but
cannot raise installation policy.

Rate limiting has independent, bounded buckets for:

- Mutations by site and client address.
- Reads by site and client address.
- Concurrent subscriptions by site and client address.
- Installation-wide Wispist work.

Initial Wispdeck allowances are:

| Bucket | Sustained allowance | Burst |
| --- | ---: | ---: |
| Reads per site and client address | 600/minute | 100 |
| Mutations per site and client address | 60/minute | 20 |
| Mutations across one site | 300/minute | 60 |
| New generated-ID documents across one site | 10,000/day | 100 |
| SSE connections per site and client address | 6 concurrent | 6 |
| SSE connections across one site | 100 concurrent | 100 |
| All Wispist requests across one installation | 6,000/minute | 1,000 |

The installation allowance is an initial Wispdeck default rather than a claim
about universal capacity. Operators may lower or raise request rates, but the
hard memory, body, storage, and queue limits remain enforced.

Client addresses are derived using Wispdeck's trusted-proxy configuration; an
untrusted forwarding header is ignored. `429` includes `Retry-After`.

Rate limiting is an availability control, not authorization. It must use bounded
memory and discard idle buckets.

No namespace may cause unbounded result sets, decoded bodies, event queues,
goroutines, open files, prepared statements, or log cardinality.

## 12. Security model

### 12.1 Trust assumptions

- Site JavaScript is fully authoritative within its own origin and granted
  collection policies.
- Client configuration and source code are public.
- An `anyone` write policy grants every visitor the same write authority.
- Exact-origin and Fetch Metadata checks reduce cross-site request abuse but do
  not defend against malicious code running in the site origin.
- A service worker owned by the site can intercept its own same-origin traffic;
  this is inherent in giving the site control of its origin.
- Wispdeck's request-binding code is trusted to supply the correct namespace,
  declaration, principal, mode, and restrictions when it calls the engine.
- SQLite files and the Wispdeck host filesystem are within the operator trust
  boundary.

### 12.2 Request protections

- Reserve `/_wispist/` before static-file lookup.
- Accept only explicitly supported methods and media types.
- Validate canonical paths and identifiers before store access.
- Limit bodies before reading or decoding.
- Evaluate policy for every operation and every streamed document.
- Require conditional writes.
- Use exact same-origin checks for unsafe browser requests.
- Use `SameSite` and host-only cookies when identity is introduced.
- Return no CORS headers in embedded mode.
- Apply request, storage, and subscription limits before expensive work.
- Do not include document values or identity credentials in ordinary logs or
  metric labels.

### 12.3 Preview protections

The existing isolated preview origin remains mandatory. A draft never runs on
the public site's origin, preventing a published site's cookies, local storage,
or service worker from controlling the draft.

The preview-session cookie only grants access to the private preview origin.
Wispdeck resolves Draft to a draft-data binding. Switching the preview UI to
Current creates a live-data binding with an unrelaxable read-only restriction.

Preview and public namespaces are selected server-side. No query parameter,
header, request body, collection name, or browser client option may select a
different namespace.

### 12.4 Future identity

Wispist's principal is intentionally provider-neutral:

```text
kind: anonymous | authenticated | capability | service
subject: opaque provider-scoped identifier
claims: bounded map of JSON scalar values
```

V1 needs only anonymous and host-asserted authenticated principals. It does not
define a public token format.

A future Wispdeck integration must not attempt to read the dashboard's cookie on
a site subdomain. It should use a short-lived, audience-bound, one-use handoff to
establish a host-only site-origin session, similar in shape to the preview
handoff. Wispist may later provide its own simple identity implementation through
the same principal interface.

Authentication answers who the caller is. Collection policy still answers what
that caller may do. Bot-attestation or proof-of-work features may reduce abuse
but must never be treated as authorization.

## 13. Failure and concurrency behavior

- A document mutation and its change entry either both commit or neither does.
- Notifications are emitted only after commit.
- If the server commits but loses the POST response, repeating the same
  idempotency key returns the committed result.
- If a conditional mutation races, exactly one matching revision succeeds.
- Store busy conditions return retryable `503`, not partial success.
- A failed policy/configuration lookup fails closed.
- An SSE disconnect loses no retained changes; the client reconnects after its
  last applied cursor.
- Duplicate SSE delivery is allowed and de-duplicated by cursor.
- Exhausted change history causes reset and relist, never silent divergence.
- Slow subscribers are disconnected before their queues grow without bound.
- Failure to transform an HTML response fails the request rather than serving a
  representation in which Wispist is unpredictably absent.

## 14. Observability and operations

Wispist exposes an optional generic `Observer` contract rather than importing a
metrics implementation. It emits bounded observations without document bodies
for requests, request latency, operation, status, Problem Details type, active
SSE connection deltas, and stream resets. The SQLite factory exposes a bounded
snapshot of open stores, stores in use, and eviction count. Wispdeck owns the
mapping of these values into its operator metrics.

The engine also writes non-sensitive request dimensions at structured debug
level, store and binding failures at error level, and puts the same per-request
correlation ID in responses and applicable error logs.

Site IDs may appear in protected operator logs but not unbounded metric labels.
Collection names, document IDs, JSON bodies, authentication tokens, cookies,
idempotency keys, and client addresses are not logged at normal levels.

Backups operate at the per-site SQLite-file boundary and must account for WAL
state. Restore and deletion are Wispdeck control-plane operations, not browser
API operations.

## 15. Compatibility and evolution

The `/v1` protocol and `/client/v1.js` path identify a major compatibility
family. V1 additions may add optional response fields, error details, or client
methods. Existing fields do not change meaning, and existing valid requests do
not become invalid within v1 except to fix a security defect.

The client ignores unknown response fields. Servers reject unknown request
fields to catch authoring mistakes.

Future likely extensions include:

- Capability edit links.
- Site-origin user sessions and simple identity.
- Document-aware policy expressions.
- Explicit draft reset, live-to-draft copy, and carefully confirmed promotion.
- Bounded exact-match queries and declared indexes.
- Batch writes with explicit transaction limits.
- User-uploaded blobs.
- A standalone Wispist host and cross-origin mode.

They must preserve the core constraints: static-site usability, no secrets in
browser code, server-enforced policy, bounded resources, and no per-site idle
compute. Arbitrary application functions and permanently running site processes
remain outside the product direction.

## 16. Delivery sequence

Implementation should proceed in vertical slices while keeping the protocol
conformance-testable:

1. **Contracts and validators**
   - Resource types, strict JSON validation, declaration parsing, errors,
     namespace binding, and authorizer interfaces.
2. **SQLite store**
   - Per-site file lifecycle, documents, revisions, changes, idempotency, quotas,
     migrations, concurrent contract tests, and backup-safe closure.
3. **HTTP CRUD protocol**
   - Same-origin enforcement, strict request limits, conditional mutations,
     pagination, errors, and conformance tests independent of Wispdeck.
4. **Wispdeck composition**
   - Reserved routing, live/draft/current-preview resolution, release-bound
     declarations, `wispist.Binding` construction, read-only override, data
     directory, engine instantiation, and host tests.
5. **Automatic client**
   - Deterministic HTML transformation, global API, CRUD ergonomics, ETag-safe
     representation handling, and browser-level tests.
6. **Realtime**
   - Transactional change log, race-free SSE hub, reset behavior, client
     reconciliation, heartbeat/write deadlines, and slow-consumer tests.
7. **Operational hardening**
   - Rate limits, store cache bounds, metrics, structured logging, race detector,
     failure injection, documentation, and an example shared checklist site.

The first user-visible acceptance test is deliberately small:

1. Upload a static itinerary site declaring `before-you-go`.
2. Open it in two independent browsers.
3. Add or check an item in one browser.
4. Observe the other browser update without refreshing.
5. Upload a new draft and mutate its checklist.
6. Verify the public checklist is unchanged.
7. Select Current in preview and verify data is visible but mutations are denied.
8. Publish the draft and verify the original live data remains intact.

That slice proves Wispist's defining promise without prematurely committing to a
general backend platform.
