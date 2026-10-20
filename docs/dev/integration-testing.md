# Integration Testing

The integration test suite runs real Caddy and caddygee-server subprocesses against a fake GCS server and a real upstream HTTP server, giving end-to-end coverage of the full deploy flow.

## Running the Tests

```bash
# Locally (requires Go toolchain)
go test -tags integration -timeout 300s -v ./integration/

# Inside Docker (mirrors CI exactly)
make test-integration
# or:
docker build -f Dockerfile.test -t caddygee-test:dev --progress plain .
docker run --rm caddygee-test:dev
```

The `integration` build tag gates all test files in the `integration/` package. Unit tests (`go test ./...`) never run them.

## Test Harness

All tests share a harness provided by `integration/harness_test.go`. The central entry point is `startGateway`:

```go
gw := startGateway(t, "test-project")
```

This single call:
1. Builds `caddy` and `caddygee-server` from source (once per test run, via `sync.Once`)
2. Starts an in-process fake GCS server
3. Starts a `caddygee-server` subprocess pointed at the fake GCS and a free TCP port
4. Starts a `caddy` subprocess with a minimal bootstrap Caddyfile
5. Registers cleanup via `t.Cleanup` so both subprocesses are killed when the test ends

### Deploying a Bundle

```go
gw.Deploy("testdata/integration/assign_message/apiproxy", "my-service", upstream.URL)
```

`Deploy` zips the bundle directory, POSTs it to the `caddygee-server` `/deploy` endpoint with an `Authorization: Bearer <project-id>` header (bypass mode), and waits for Caddy to hot-reload.

The `upstream.URL` placeholder is substituted into all `<URL>` tags in the bundle's target endpoint XML before uploading.

For extra substitutions beyond the upstream URL:

```go
gw.DeployWithSubs("testdata/integration/kvm/apiproxy", "kvm-svc", upstream.URL, map[string]string{
    "JWKS_URI_PLACEHOLDER": jwksServer.URL,
})
```

### Making Requests

```go
resp := gw.GET("/test/my-service/path")
resp := gw.GET("/test/my-service/path", "X-Custom-Header", "value")
resp := gw.POST("/test/my-service/path", "application/json", body)
```

These return a `*http.Response`. The test is responsible for closing the body.

## Fake GCS

The `fakeGCS` in-process server implements the minimal GCS API surface used by the Go storage client:

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/storage/v1/b/{bucket}` | Bucket exists check |
| `GET` | `/storage/v1/b/{bucket}/o` | List objects |
| `GET` | `/storage/v1/b/{bucket}/o/{name}` | Object metadata |
| `GET` | `/storage/v1/b/{bucket}/o/{name}?alt=media` | Download |
| `POST` | `/upload/storage/v1/b/{bucket}/o?uploadType=multipart` | Upload |
| `GET` | `/{bucket}/{name}` | XML-API path (used by Go client with `STORAGE_EMULATOR_HOST`) |

**Important:** when `STORAGE_EMULATOR_HOST` is set, the Go GCS client issues downloads via the XML-API path `GET /{bucket}/{object}`, not the JSON API path. The fake GCS handles both.

You can pre-seed objects:

```go
gcs.Put("my-bucket", "project-id/service.caddyfile", fragmentContent)
```

And read them back for assertions:

```go
content, ok := gcs.Get("my-bucket", "project-id/service.caddyfile")
```

## Bypass Auth

The `CADDYGEE_BYPASS_AUTH=1` environment variable skips OIDC token validation in `caddygee-server`. When set, the raw Bearer token value is used as the project ID directly. The harness always sets this.

## Writing a New Policy Test

1. **Create a testdata bundle** under `testdata/integration/<policy_name>/apiproxy/`. The minimal layout:

   ```
   testdata/integration/my_policy/
   └── apiproxy/
       ├── MyProxy.xml          # root descriptor
       ├── proxies/
       │   └── default.xml      # base path /test/my-policy, flows, route rules
       ├── targets/
       │   └── default.xml      # URL: UPSTREAM_PLACEHOLDER
       └── policies/
           └── MyPolicy.xml     # policy config
   ```

   Use `UPSTREAM_PLACEHOLDER` as the upstream URL — the harness replaces it at deploy time.

2. **Write the test** in `integration/policies_test.go` (or a new file with `//go:build integration`):

   ```go
   func TestPolicy_MyPolicy(t *testing.T) {
       upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           // inspect what reached the upstream
           w.WriteHeader(http.StatusOK)
       }))
       defer upstream.Close()

       gw := startGateway(t, "test")
       gw.Deploy("testdata/integration/my_policy/apiproxy", "my-policy", upstream.URL)

       resp := gw.GET("/test/my-policy/")
       defer resp.Body.Close()

       if resp.StatusCode != http.StatusOK {
           t.Fatalf("expected 200, got %d", resp.StatusCode)
       }
   }
   ```

3. **Test from the outside in.** Verify observable effects: response status, response headers, upstream-received headers, GCS object contents. Don't reach into internal state.

## Writing a Multi-Policy E2E Test

For scenarios where several policies interact, use a single bundle with multiple flows or a bundle that exercises multiple policies in sequence. See `integration/e2e_test.go` for examples of:

- Deploy + hot-reload (multiple deploys to the same gateway)
- Two services running simultaneously on the same Caddy instance
- Response-phase mutations observed on the client side

## Harness Internals

### Binary Build

Binaries are built once per `go test` invocation using `sync.Once`. The binary outputs land in a temp directory and are shared across all tests in the run. In Docker (`Dockerfile.test`), the binaries are pre-built in the `RUN` layer so the first test doesn't pay the build cost.

### Port Allocation

The harness calls `net.Listen("tcp", "127.0.0.1:0")` to find free ports, then immediately closes the listener before passing the port to the subprocess. There is a small TOCTOU window, but in practice this is reliable in a CI environment.

### Caddy Admin API Consistency

Each `startGateway` call picks a free port for the Caddy admin API. This port is threaded through to `caddygee-server` via the `CADDY_ADMIN_ADDR` environment variable. `caddygee-server` embeds this address in the merged Caddyfile's `admin` directive via `Options.AdminAddress`. After a hot-reload, Caddy binds the admin API to the same address — subsequent deploys continue to work.

### Hot-Reload Wait

After deploying a fragment, the harness polls the Caddy admin API's `/config/` endpoint until the config changes or a timeout is reached. This avoids fixed `time.Sleep` calls.

## CI

Integration tests run as a separate `integration` job in `.github/workflows/ci.yml`, in parallel with the `test` (unit) and `build` (binary compilation) jobs:

```yaml
integration:
  name: Integration tests
  runs-on: ubuntu-latest
  steps:
    - uses: actions/checkout@v4
    - uses: docker/setup-buildx-action@v3
    - run: |
        docker build --file Dockerfile.test --tag caddygee-test:ci --progress plain .
        docker run --rm caddygee-test:ci
```

The `Dockerfile.test.dockerignore` file sits alongside `Dockerfile.test` and overrides the default `.dockerignore` for that build context. It includes `testdata/` and `*_test.go` (which are excluded from the production image) while still excluding `.git/` and `terraform/`.

## Troubleshooting

**`testdata directory does not exist`** — the `Dockerfile.test.dockerignore` file is missing or the build is using the wrong dockerignore. Confirm `Dockerfile.test.dockerignore` exists in the repo root.

**`caddy adapt: config is unchanged` on second deploy** — pass `--config -` to `caddy adapt` when piping a Caddyfile over stdin. Without it, Caddy looks for an adjacent `Caddyfile` file in the subprocess working directory and uses that instead of stdin.

**`connection refused` to Caddy admin API after hot-reload** — the merged Caddyfile's `admin` directive must match the admin port that was used to start Caddy. Ensure `Options.AdminAddress` is threaded through `MergeFragments` correctly.

**`storage: object doesn't exist` for a known object** — when `STORAGE_EMULATOR_HOST` is set, the GCS client uses the XML-API path (`/{bucket}/{object}`) for downloads. Confirm the fake GCS handles this path.
