# Shadow-Armor developer tasks. Users never need this: download the release binary.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.3.1-dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X github.com/Shadow-Security-official/Shadow-Armor/internal/version.Version=$(VERSION:v%=%) \
           -X github.com/Shadow-Security-official/Shadow-Armor/internal/version.Commit=$(COMMIT) \
           -X github.com/Shadow-Security-official/Shadow-Armor/internal/version.Date=$(DATE)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
NFPM      := GOTOOLCHAIN=auto go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0
PKG_VERSION = $(patsubst v%,%,$(VERSION))

.PHONY: build binaries packages sbom dist test lint check docs clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/sdw-armor ./cmd/sdw-armor

# Release artifacts: static binaries, .deb/.rpm packages, CycloneDX SBOM, SHA256SUMS.
dist: binaries packages sbom
	cd dist && sha256sum sdw-armor-* sdw-armor_* sdw-armor.cdx.json > SHA256SUMS

binaries:
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  echo "building $$os/$$arch"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/sdw-armor-$$os-$$arch ./cmd/sdw-armor || exit 1; \
	done

packages: binaries
	@for arch in amd64 arm64; do \
	  sed -e "s/\$${PKG_ARCH}/$$arch/g" -e "s/\$${PKG_VERSION}/$(PKG_VERSION)/g" packaging/nfpm.yaml > dist/.nfpm-$$arch.yaml; \
	  for fmt in deb rpm; do \
	    $(NFPM) package --config dist/.nfpm-$$arch.yaml --packager $$fmt --target dist/ || exit 1; \
	  done; \
	  rm -f dist/.nfpm-$$arch.yaml; \
	done

sbom: binaries
	go run ./tools/sbom -version $(PKG_VERSION) -o dist/sdw-armor.cdx.json dist/sdw-armor-linux-* dist/sdw-armor-darwin-*

test:
	go vet ./...
	go test ./...

lint:
	golangci-lint run ./...

check:
	cinc-auditor check profile --no-color

docs:
	go run ./cmd/sdw-armor list --markdown > docs/CONTROLS.md

clean:
	rm -rf dist
