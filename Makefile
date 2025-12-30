ECHO                = @echo
QUIET               = @
ifdef V
QUIET               =
ECHO                = @true
endif
CC                  := gcc
CXX                 := g++
LXX                 := g++
CFLAGS              := -O0 -Wall -Werror -ggdb

LDLIBS              ?= -Bstatic
LDLIBS              += -lpcap
LDLIBS              += -lsrtp2

OBJ_DIR             ?= objs
SRC_DIR             := src
SEPARATOR           := "****************************"
APP                 := rtp-pcap

CSRCS               := hexutils.c
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
	@echo "COBJS           : $(COBJS)"
	@echo "CPPOBJS         : $(CPPOBJS)"
	@echo "CFLAGS          : $(CFLAGS)"

clean: app-clean ## Cleanup application files

format: ## Perform linting of source files
	clang-format -Werror -i src/*

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

app-clean: ## Cleanup the application
	rm -rf $(OBJ_DIR) $(APP)
