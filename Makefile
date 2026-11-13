ECHO                = @echo
QUIET               = @
ifdef V
QUIET               =
ECHO                = @true
endif
CC                  := gcc
CXX                 := g++
LXX                 := g++
INCLUDE_SRTP        ?= 1
COVERAGE            ?= 0
CFLAGS              := -O0 -Wall -Werror -ggdb -DINCLUDE_SRTP=$(INCLUDE_SRTP)
CXXFLAGS            := -std=c++11 -Ithird_party/CLI11/include
LDFLAGS             := -Bstatic

ifneq ("$(COVERAGE)", "0")
CFLAGS              += --coverage -fprofile-arcs
LDFLAGS             += --coverage
endif
EXTRA_CFLAGS        ?= 
EXTRA_LDFLAGS       ?=

LDFLAGS             += -lpcap
ifneq ("$(INCLUDE_SRTP)", "0")
LDFLAGS             += -lsrtp2
endif

OBJ_DIR             ?= objs
COVERAGE_OBJ_DIR    ?= objs-cov
COVERAGE_DIR        ?= coverage
COVERAGE_INDEX      := $(COVERAGE_DIR)/index.html
# CLI11 is included from several translation units. gcovr then tries to merge
# the same inline functions and aborts. Drop every vendored source from the report.
GCOVR_FLAGS         := --exclude third_party/
SRC_DIR             := src
SEPARATOR           := "****************************"
APP                 := rtp-pcap

CSRCS               := hexutils.c
CSRCS               += base64.c
CPPSRCS             := arguments.cpp
CPPSRCS             += packet_utilities.cpp
CPPSRCS             += time_utilities.cpp
CPPSRCS             += rtp_pcap.cpp
CPPSRCS             += action_summary.cpp
CPPSRCS             += action_details.cpp
CPPSRCS             += action_list.cpp
CPPSRCS             += action_stats.cpp
ifneq ("$(INCLUDE_SRTP)", "0")
CPPSRCS             += action_srtp.cpp
endif

COBJS      = $(patsubst %.c,$(OBJ_DIR)/%.o,$(CSRCS))
CPPOBJS    = $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(CPPSRCS))

###############################
# targets

# the first target is the default, so just run help
help: ## This message
	@echo "===================="
	@echo " Available Commands"
	@echo "===================="
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m\033[0m\n"} /^[$$()% a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

###########
##@ General
env: ## Print select environment variables
	@echo $(SEPARATOR)
	@echo "SRC_DIR         : $(SRC_DIR)"
	@echo "OBJ_DIR         : $(OBJ_DIR)"
	@echo "COVERAGE_OBJ_DIR: $(COVERAGE_OBJ_DIR)"
	@echo "COBJS           : $(COBJS)"
	@echo "CPPOBJS         : $(CPPOBJS)"
	@echo "CFLAGS          : $(CFLAGS)"
	@echo "CXXFLAGS        : $(CXXFLAGS)"
	@echo "EXTRA_CFLAGS    : $(EXTRA_CFLAGS)"
	@echo "LDFLAGS         : $(LDFLAGS)"
	@echo "EXTRA_LDFLAGS   : $(EXTRA_LDFLAGS)"
	@echo "COVERAGE_DIR    : $(COVERAGE_DIR)"
	@echo "COVERAGE_INDEX  : $(COVERAGE_INDEX)"

prereq: ## Install prerequisites (e.g. gcovr)
	pip3 install gcovr

clean: app-clean ## Cleanup application files

format: ## Perform linting of source files
	clang-format -Werror -i src/*

uncommitted: ## Check for uncommitted changes
	make -f uncommitted.mk check

check-format: format uncommitted ## Formats source and looks for changes

all: format clean coverage ## build and test

###############################
##@ Build
$(OBJ_DIR):
	$(ECHO) "Making $@..."
	$(QUIET)mkdir -p $@

$(CPPOBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.cpp $(OBJ_DIR)
	$(ECHO) "Compiling $<..."
	$(QUIET)$(CXX) -c -o $@ $(CFLAGS) $(CXXFLAGS) $(EXTRA_CFLAGS) $<

$(COBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c $(OBJ_DIR)
	$(ECHO) "Compiling $<..."
	$(QUIET)$(CC) -c -o $@ $(CFLAGS) $(EXTRA_CFLAGS) $<

$(APP): $(COBJS) $(CPPOBJS)
	$(ECHO) "Linking $@..."
	$(QUIET)$(LXX) -o $@ $(COBJS) $(CPPOBJS) $(LDFLAGS) $(EXTRA_LDFLAGS)

app: $(APP) ## Build the application

test: ## Run test script
	INCLUDE_SRTP="$(INCLUDE_SRTP)" ./test.sh

app-clean: ## Cleanup the application
	rm -rf $(OBJ_DIR) $(COVERAGE_OBJ_DIR) $(COVERAGE_DIR) $(APP)

###############################
##@ Coverage
.PHONY: test coverage coverage-run coverage-report

coverage: ## Build with coverage, run tests, and report
	rm -rf $(COVERAGE_OBJ_DIR) $(COVERAGE_DIR) $(APP)
	COVERAGE=1 $(MAKE) app OBJ_DIR=$(COVERAGE_OBJ_DIR)
	$(MAKE) coverage-run

coverage-run: test coverage-report ## Run the coverage tests (without rebuild)

coverage-report: ## Summarize coverage from the latest instrumented test run
	python3 -m gcovr $(GCOVR_FLAGS)
	rm -rf $(COVERAGE_DIR)
	mkdir -p $(COVERAGE_DIR)
	python3 -m gcovr $(GCOVR_FLAGS) --html-details $(COVERAGE_INDEX)
	$(ECHO) "Full details avalable at $(COVERAGE_INDEX)"
