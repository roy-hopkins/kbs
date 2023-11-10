AS_TYPE ?= coco-as
HTTPS_CRYPTO ?= rustls
POLICY_ENGINE ?=

COCO_AS_INTEGRATION_TYPE ?= builtin

INSTALL_DESTDIR ?= /usr/local/bin

CONFIGURATION ?= DEBUG

ifeq ($(CONFIGURATION), DEBUG)
	CARGO_CONFIGURATION = 
	TARGET_DIR = target/debug
else
	CARGO_CONFIGURATION = --release
	TARGET_DIR = target/release
endif

ifeq ($(AS_TYPE), coco-as)
  AS_FEATURE = $(AS_TYPE)-$(COCO_AS_INTEGRATION_TYPE)
else
  AS_FEATURE = $(AS_TYPE)
endif

build: background-check-kbs

.PHONY: background-check-kbs
background-check-kbs:
	cargo build $(CARGO_CONFIGURATION) --no-default-features --features $(AS_FEATURE),resource,$(HTTPS_CRYPTO),$(POLICY_ENGINE)

.PHONY: passport-issuer-kbs
passport-issuer-kbs:
	cargo build $(CARGO_CONFIGURATION) --no-default-features --features $(AS_FEATURE),$(HTTPS_CRYPTO)
	mv $(TARGET_DIR)/kbs $(TARGET_DIR)/issuer-kbs

.PHONY: passport-resource-kbs
passport-resource-kbs:
	cargo build $(CARGO_CONFIGURATION) --no-default-features --features $(HTTPS_CRYPTO),resource,$(POLICY_ENGINE)
	mv $(TARGET_DIR)/kbs $(TARGET_DIR)/resource-kbs

install-kbs:
	install -D -m0755 $(TARGET_DIR)/kbs $(INSTALL_DESTDIR)
	install -D -m0755 $(TARGET_DIR)/kbs-client $(INSTALL_DESTDIR)

install-issuer-kbs:
	install -D -m0755 $(TARGET_DIR)/issuer-kbs $(INSTALL_DESTDIR)
	install -D -m0755 $(TARGET_DIR)/kbs-client $(INSTALL_DESTDIR)

install-resource-kbs:
	install -D -m0755 $(TARGET_DIR)/resource-kbs $(INSTALL_DESTDIR)
	install -D -m0755 $(TARGET_DIR)/kbs-client $(INSTALL_DESTDIR)

uninstall:
	rm -rf $(INSTALL_DESTDIR)/kbs $(INSTALL_DESTDIR)/kbs-client $(INSTALL_DESTDIR)/issuer-kbs $(INSTALL_DESTDIR)/resource-kbs

check:
	cargo test --lib

lint:
	cargo clippy -- -D warnings  -Wmissing-docs -A clippy::enum_variant_names

format:
	cargo fmt -- --check --config format_code_in_doc_comments=true

clean:
	cargo clean

