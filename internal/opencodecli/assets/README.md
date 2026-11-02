# OpenCode runtime asset

`go run ./cmd/bundle-opencode` compresses the installed native OpenCode binary
into `opencode.gz`. The generated asset is ignored by Git. Vercel builds with
`-tags opencode_bundle` to include the engine in the Go executable; the runtime
extracts it into private temporary storage.
