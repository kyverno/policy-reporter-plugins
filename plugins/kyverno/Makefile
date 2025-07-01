
#########
# TOOLS #
#########

TOOLS_DIR                  ?= $(PWD)/.tools
CONTROLLER_GEN             := $(TOOLS_DIR)/controller-gen
CONTROLLER_GEN_VERSION     ?= v0.17.3
CLIENT_GEN                 ?= $(TOOLS_DIR)/client-gen
CODE_GEN_VERSION           ?= v0.32.4
REGISTER_GEN               ?= $(TOOLS_DIR)/register-gen
DEEPCOPY_GEN               ?= $(TOOLS_DIR)/deepcopy-gen

###########
# CODEGEN #
###########

PACKAGE                     := github.com/kyverno/policy-reporter/kyverno-plugin
CLIENT_PACKAGE              := $(PACKAGE)/pkg/crd/client
CLIENTSET_PACKAGE           := $(CLIENT_PACKAGE)/clientset

$(CLIENT_GEN):
	@echo Install client-gen... >&2
	@GOBIN=$(TOOLS_DIR) go install k8s.io/code-generator/cmd/client-gen@$(CODE_GEN_VERSION)

$(REGISTER_GEN):
	@echo Install register-gen... >&2
	@GOBIN=$(TOOLS_DIR) go install k8s.io/code-generator/cmd/register-gen@$(CODE_GEN_VERSION)

$(DEEPCOPY_GEN):
	@echo Install deepcopy-gen... >&2
	@GOBIN=$(TOOLS_DIR) go install k8s.io/code-generator/cmd/deepcopy-gen@$(CODE_GEN_VERSION)

.PHONY: codegen-api-register
codegen-api-register: ## Generate API types registrations
codegen-api-register: $(REGISTER_GEN)
	@echo Generate registration... >&2
	@$(REGISTER_GEN) --go-header-file=./scripts/boilerplate.go.txt --output-file zz_generated.register.go ./pkg/crd/api/...

.PHONY: codegen-api-deepcopy
codegen-api-deepcopy: ## Generate API deep copy functions
codegen-api-deepcopy: $(DEEPCOPY_GEN)
	@echo Generate deep copy functions... >&2
	@$(DEEPCOPY_GEN) --go-header-file ./scripts/boilerplate.go.txt --output-file zz_generated.deepcopy.go ./pkg/crd/api/...

.PHONY: codegen-client-clientset
codegen-client-clientset: ## Generate clientset
codegen-client-clientset: $(CLIENT_GEN)
	@echo Generate clientset... >&2
	@rm -rf ./pkg/crd/client/clientset && mkdir -p ./pkg/crd/client/clientset
	@$(CLIENT_GEN) \
		--go-header-file ./scripts/boilerplate.go.txt \
		--clientset-name versioned \
		--output-dir ./pkg/crd/client/clientset \
		--output-pkg $(CLIENTSET_PACKAGE) \
		--input-base github.com/kyverno/policy-reporter/kyverno-plugin \
		--input ./pkg/crd/api/kyverno/v1 \
		--input ./pkg/crd/api/kyverno/v2beta1 \
		--input ./pkg/crd/api/policyreport/v1alpha2 \
		--input ./pkg/crd/api/policies.kyverno.io/v1alpha1