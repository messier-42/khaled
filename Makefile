

## User configurable variables
##############################################################################

# Build directory.
BUILD_DIR ?= build

# Set to 'podman' or 'docker'.
CONTAINER_TOOL ?= podman

REGCTL ?= regctl
GOLANGCI_LINT ?= golangci-lint
GRYPE ?= grype
HELM ?= helm

GOLANGCI_ARGS ?= --path-prefix @
GRYPE_ARGS ?=

ifneq ($(FIX),)
GOLANGCI_ARGS := $(GOLANGCI_ARGS) --fix
endif
ifneq ($(NEW),)
GOLANGCI_ARGS := $(GOLANGCI_ARGS) --new
endif


##
##############################################################################
-include Makefile.config
-include $(BUILD_DIR)/Makefile.config

# Use bash. Do not continue executing when a shell command fails.
SHELL := /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

GOROOT := $(shell PATH="$(PQGO_PATH)/bin:$$PATH" go env GOROOT)
export GOROOT
PATH := $(GOROOT)/bin:$(PATH)

MODULE_NAMES = khaled
MODULE_NAMES_ALL = $(MODULE_NAMES)
IMAGE_NAMES = khaled
LAST_BUILD_TAG = oci.local/$(1):last-build

OUT_DIR ?= $(BUILD_DIR)/out
BIN_DIR ?= $(OUT_DIR)/bin
OCI_DIR ?= $(OUT_DIR)/oci
DIST_DIR ?= $(OUT_DIR)/dist
INT_DIR ?= $(BUILD_DIR)/int
LINT_REPORTS_DIR ?= $(BUILD_DIR)/lint-reports
DIST_TREE_DIR ?= $(INT_DIR)/dist-tree

CABE_GO_DIR ?= ../cabe-go

# Temporary
CHART_DIR ?= $(OUT_DIR)/charts
CHART_SRC_DIR ?= chart/khaled

KHALED_VERSION ?= $(shell if [[ -z "$$TARGET_VERSION" ]]; then k="$$(git describe --tags --exact-match 2>/dev/null || true)"; else k="$$TARGET_VERSION"; fi; if [[ $$k =~ ^v[0-9].*$$ ]]; then echo "$$k"; else echo v0.0.0; fi)

Q=@
ifeq ($(V),1)
Q=
endif

INFO=@echo -e "\t$(1)\t$(2)"

.PHONY: all
all: oci-images $(BIN_DIR)/sterile-khaled chart ## Build everything

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf "$(BUILD_DIR)"

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

print-%:
	@echo $($*)


##@ Building

.PHONY: oci-images
oci-images: $(foreach x, $(IMAGE_NAMES), $(OCI_DIR)/$(x).oci) ## Build OCI images

$(OCI_DIR)/khaled.oci:
	$(Q)mkdir -p "$(OCI_DIR)"
	$(call INFO,OCI-BUILD,$@)
	$(Q)./scripts/Containerfile.sh khaled | \
	  $(CONTAINER_TOOL) build -t "$(call LAST_BUILD_TAG,khaled)" \
	    --build-context cabe-go=$(CABE_GO_DIR) \
	    -f - .
	$(call INFO,OCI-SAVE,$@)
	$(Q)$(CONTAINER_TOOL) save --format oci-archive --output "$@.tmp" "$(call LAST_BUILD_TAG,khaled)"
	$(Q)mv "$@.tmp" "$@"

$(BIN_DIR)/khaled:
	go build -o "$@" ./cmd/khaled

$(BIN_DIR)/sterile-khaled: $(OCI_DIR)/khaled.oci
	$(Q)mkdir -p "$(BIN_DIR)"
	$(call INFO,EXTRACT,$@)
	$(Q)CID=$$("$(CONTAINER_TOOL)" create "$(call LAST_BUILD_TAG,khaled)") && \
	  $(CONTAINER_TOOL) cp "$$CID:/khaled" "$@"; $(CONTAINER_TOOL) rm "$$CID"; chmod +x "$@"

.PHONY: chart
chart:
	$(Q)mkdir -p "$(CHART_DIR)"
	$(call INFO,HELM-LINT,$(CHART_SRC_DIR))
	$(Q)$(HELM) lint "$(CHART_SRC_DIR)"
	$(call INFO,HELM-PACK,$(CHART_DIR))
	$(Q)$(HELM) package "$(CHART_SRC_DIR)" -d "$(CHART_DIR)"


##@ Testing (for development)

KHALED_CONFIG ?= doc/dev-config.yaml
KHALED_ARGS   ?=

.PHONY: run
run: ## Run khaled against a developer config (anonymous auth, localhost)
	$(Q)mkdir -p build/dev/keystorage
	go run ./cmd/khaled --config $(KHALED_CONFIG) $(KHALED_ARGS)

.PHONY: test utest utest-% integration
test: utest integration ## Run unit and integration tests
.NOTPARALLEL: test

utest: $(foreach x, $(MODULE_NAMES), utest-$(x)) ## Run unit tests for all modules
.NOTPARALLEL: utest

utest-khaled:
	$(Q)n="$(patsubst utest-%,%,$@)"; \
	echo "=== Running $$n tests..."; \
	go test -race -count=1 ./...

integration: ## Run in-process integration tests
	$(Q)echo "=== Running integration tests..."; \
	go test -race -count=1 -tags=integration ./test/...

.PHONY: kutest cabetool-oci kutest-oci-rebuild
$(OCI_DIR)/cabetool.oci:
	$(Q)mkdir -p "$(OCI_DIR)"
	$(call INFO,OCI-BUILD,$@)
	$(Q)$(CONTAINER_TOOL) build -t "$(call LAST_BUILD_TAG,cabetool)" \
	  -f $(shell pwd)/test/kutest/Containerfile.cabetool \
	  "$(CABE_GO_DIR)"
	$(call INFO,OCI-SAVE,$@)
	$(Q)$(CONTAINER_TOOL) save --format oci-archive --output "$@.tmp" "$(call LAST_BUILD_TAG,cabetool)"
	$(Q)mv "$@.tmp" "$@"
cabetool-oci: $(OCI_DIR)/cabetool.oci ## Build cabetool OCI archive (from $(CABE_GO_DIR))

kutest-oci-rebuild:
	$(Q)rm -f "$(OCI_DIR)/khaled.oci" "$(OCI_DIR)/cabetool.oci"
	$(Q)$(MAKE) -s "$(OCI_DIR)/khaled.oci" "$(OCI_DIR)/cabetool.oci"

kutest: kutest-oci-rebuild chart ## Run kind-based multi-process integration tests
	$(Q)echo "=== Running kutest..."; \
	export KUTEST_OCI_IMAGES_PATH="$$(realpath $(OCI_DIR))"; \
	export KUTEST_HELM_CHART="$$(realpath $$(ls $(CHART_DIR)/khaled-*.tgz | head -1))"; \
	export KUTEST_TARGET_TYPE="$${KUTEST_TARGET_TYPE:-builtin-kind}"; \
	go -C test/kutest test -tags=integration_k8s -count=1 -timeout=0 -v $(KUTEST_ARGS) ./...

grype: $(foreach x, $(IMAGE_NAMES), $(OCI_DIR)/$(x).oci) ## Run 'grype' vulnerability scanning tool
	$(Q)$(GRYPE) -c .github/grype.yaml dir:./
	$(Q)for x in $^; do \
	  $(GRYPE) -c .github/grype.yaml $(GRYPE_ARGS) oci-archive:$$x; \
	done


##@ Linting (for development)

.PHONY: lint lint-ci lint-ci-%
lint: lint-ci ## Run all linters
.NOTPARALLEL: lint

lint-ci: $(foreach x, $(MODULE_NAMES_ALL), lint-ci-$(x)) ## Run golangci-lint linters for all modules
.NOTPARALLEL: lint-ci

lint-ci-%:
	$(Q)n="$(patsubst lint-ci-%,%,$@)"; \
	echo "=== Running $$n golangci-lint..."; \
	mkdir -p "$(LINT_REPORTS_DIR)"; \
	r="$$(realpath "$(LINT_REPORTS_DIR)/golangci-lint")"; \
	mkdir -p "$$r"; \
	GOTOOLCHAIN=local "$(GOLANGCI_LINT)" -c "$(shell pwd)/.github/golangci.yaml" run \
	  --color always \
	  --output.text.path stdout \
	  --output.sarif.path "$$r/$$n.sarif" \
	  --output.json.path "$$r/$$n.json" \
	  $(GOLANGCI_ARGS) ./... | \
	  tee "$$r/$$n.text"

fmt:
	$(Q)echo "=== Formatting (golangci-lint)..."; \
	GOTOOLCHAIN=local "$(GOLANGCI_LINT)" -c "$(shell pwd)/.github/golangci.yaml" fmt
