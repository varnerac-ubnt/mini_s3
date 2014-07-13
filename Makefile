ERL = $(shell which erl)

ERLFLAGS= -pa $(CURDIR)/.eunit -pa $(CURDIR)/ebin -pa $(CURDIR)/*/ebin

REBAR=$(shell which rebar)
ifeq ($(REBAR),)
$(error "Rebar not available on this system")
endif

DEPSOLVER_PLT=$(CURDIR)/.depsolver_plt

DIALYZER_OPTS= -Wunmatched_returns -Werror_handling -Wrace_conditions
all: build

.PHONY: get-deps build-deps

$(DEPSOLVER_PLT):
	-dialyzer --output_plt $(DEPSOLVER_PLT) --build_plt \
		--apps erts kernel stdlib crypto public_key ssh ssl syntax_tools \
		mnesia xmerl inets asn1 -r deps

get-deps:
	$(REBAR) g-d

build-deps:
	$(REBAR) co

build:
	$(REBAR) co skip_deps=true

eunit: build
	$(REBAR) eunit skip_deps=true -v

ct:
	$(REBAR) ct skip_deps=true -v

build_plt: $(DEPSOLVER_PLT) build

dialyzer: $(DEPSOLVER_PLT) build
	-dialyzer --verbose --plt $(DEPSOLVER_PLT) $(DIALYZER_OPTS) -r ebin

typer: $(DEPSOLVER_PLT)
	typer --plt $(DEPSOLVER_PLT) -r ./src -I ./include -I ./deps

edoc:
	$(REBAR) doc skip_deps=true

clean:
	$(REBAR) clean

distclean: clean
	rm -f $(DEPSOLVER_PLT)
	rm -rf $(CURDIR)/deps/
	rm -rf $(CURDIR)/logs/
	rm -rf $(CURDIR)/doc/

precommit: distclean get-deps build-deps ct edoc dialyzer
