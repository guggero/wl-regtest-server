.PHONY: build test test-race fmt fmt-check itest

build:
	go build -o bin/wl-regtest-server ./cmd/wl-regtest-server

test:
	go test -timeout=2m ./internal/...

test-race:
	go test -race -timeout=5m ./internal/...

fmt:
	goformat -w $$(rg --files -g '*.go')

fmt-check:
	goformat -check $$(rg --files -g '*.go')

itest:
	WL_INTEGRATION=1 go test -count=1 -timeout=3m -v -run='^TestExpirySweepBitcoin$$' ./internal/server
	WL_INTEGRATION=1 go test -tags='wavewalletrpc swapruntime' -count=1 -timeout=20m -v ./itest
