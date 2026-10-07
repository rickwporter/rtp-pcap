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
CFLAGS              := -O0 -Wall -Werror -ggdb -DINCLUDE_SRTP=$(INCLUDE_SRTP)

LDLIBS              ?= -Bstatic
LDLIBS              += -lpcap
ifneq ("$(INCLUDE_SRTP)", "0")
LDLIBS              += -lsrtp2
endif

OBJ_DIR             ?= objs
COVERAGE_OBJ_DIR    ?= objs-cov
COVERAGE_DIR        ?= coverage
GCOV                ?= gcov
SRC_DIR             := src
SEPARATOR           := "****************************"
APP                 := rtp-pcap

CSRCS               := hexutils.c
CSRCS               += base64.c
CPPSRCS             := rtp_pcap.cpp

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
print_env: ## Print select environment variables
	@echo $(SEPARATOR)
	@echo "SRC_DIR         : $(SRC_DIR)"
	@echo "OBJ_DIR         : $(OBJ_DIR)"
	@echo "COVERAGE_OBJ_DIR: $(COVERAGE_OBJ_DIR)"
	@echo "COVERAGE_DIR    : $(COVERAGE_DIR)"
	@echo "COBJS           : $(COBJS)"
	@echo "CPPOBJS         : $(CPPOBJS)"
	@echo "CFLAGS          : $(CFLAGS)"

clean: app-clean ## Cleanup application files

format: ## Perform linting of source files
	clang-format -Werror -i src/*

uncommitted: ## Check for uncommitted changes
	make -f uncommitted.mk check

check-format: format uncommitted ## Formats source and looks for changes

###############################
##@ Build
$(OBJ_DIR):
	$(ECHO) "Making $@..."
	$(QUIET)mkdir -p $@

$(CPPOBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.cpp $(OBJ_DIR)
	$(ECHO) "Compiling $<..."
	$(QUIET)$(CXX) -c -o $@ $(CFLAGS) $<

$(COBJS): $(OBJ_DIR)/%.o : $(SRC_DIR)/%.c $(OBJ_DIR)
	$(ECHO) "Compiling $<..."
	$(QUIET)$(CC) -c -o $@ $(CFLAGS) $<

$(APP): $(COBJS) $(CPPOBJS)
	$(ECHO) "Linking $(APP)..."
	$(QUIET)$(LXX) -o $(APP) $(COBJS) $(CPPOBJS) $(LDFLAGS) $(LDLIBS)

app: $(APP) ## Build the application

test: ## Run test script
	./test.sh

app-clean: ## Cleanup the application
	rm -rf $(OBJ_DIR) $(COVERAGE_OBJ_DIR) $(COVERAGE_DIR) $(APP)
	rm -f *.gcov

###############################
##@ Coverage
.PHONY: test coverage coverage-report

coverage: ## Build with coverage, run tests, and report
	rm -rf $(COVERAGE_OBJ_DIR) $(COVERAGE_DIR) $(APP)
	rm -f *.gcov
	$(MAKE) app OBJ_DIR=$(COVERAGE_OBJ_DIR) CFLAGS="$(CFLAGS) --coverage" LDFLAGS="$(LDFLAGS) --coverage"
	$(MAKE) test; status=$$?; \
	$(MAKE) coverage-report; report=$$?; \
	if [ $$status -ne 0 ]; then exit $$status; fi; \
	exit $$report

coverage-report: ## Summarize coverage from the latest instrumented test run
	$(ECHO) $(SEPARATOR)
	$(ECHO) "Coverage report: $(COVERAGE_DIR)/summary.txt"
	$(QUIET)mkdir -p $(COVERAGE_DIR)
	$(QUIET)rm -f *.gcov
	$(QUIET)LC_ALL=C $(GCOV) -b -r -p -o $(COVERAGE_OBJ_DIR) $(addprefix $(SRC_DIR)/,$(CSRCS) $(CPPSRCS)) > $(COVERAGE_DIR)/gcov.txt
	cat $(COVERAGE_DIR)/gcov.txt
