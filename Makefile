# Copyright 2019 MesaTEE Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
#

MULTIFS_PROJECT_ROOT ?= $(CURDIR)
MULTIFS_OUT_DIR ?= /tmp/mfs
MULTIFS_LIB_NAME ?= libmfs.a
MULTIFS_DLL_NAME ?= libmfs.so
MULTIFS_LIB_DIR := mfslibc
MULTIFS_BIN_DIR := $(MULTIFS_PROJECT_ROOT)/bin

PROJECT_ROOT := $(MULTIFS_PROJECT_ROOT)
OUT_DIR := $(MULTIFS_OUT_DIR)

INCLUDE += -I$(PROJECT_ROOT) -I$(PROJECT_ROOT)/inc
CXXFLAGS += -Werror -U__STRICT_ANSI__ -std=c++11 -lpthread -fPIC -g
CXXFLAGS += -Wno-unused-local-typedefs -Wno-shadow -Wno-missing-field-initializers -Wno-unused-parameter

ABS_SRC := $(wildcard $(PROJECT_ROOT)/$(MULTIFS_LIB_DIR)/*.cpp)
SORTED_ABS_SRC := $(sort $(ABS_SRC))
SORTED_ABS_OBJ := $(SORTED_ABS_SRC:.cpp=.o)

ABS_OBJ := $(patsubst $(MULTIFS_PROJECT_ROOT)/%,$(OUT_DIR)/%,$(SORTED_ABS_OBJ))
SRC := $(ABS_SRC)
OBJ := $(ABS_OBJ)

$(OUT_DIR)/%.o: $(MULTIFS_PROJECT_ROOT)/%.cpp
	mkdir -p $(OUT_DIR)/$(MULTIFS_LIB_DIR)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -c $< -o $@

TARGET := $(OUT_DIR)/$(MULTIFS_LIB_NAME)
TARGETSO := $(MULTIFS_BIN_DIR)/$(MULTIFS_DLL_NAME)

MFSSRV_DIR := mfssrv
MFSSRV_SRC := $(wildcard $(PROJECT_ROOT)/$(MFSSRV_DIR)/*.cpp)
SORTED_MFSSRV_SRC := $(sort $(MFSSRV_SRC))
SORTED_MFSSRV_OBJ := $(SORTED_MFSSRV_SRC:.cpp=.o)
MFSSRV := $(MULTIFS_PROJECT_ROOT)/bin/mfssrv
MFSSRV_DEPOPT := -lpthread

MFSDEMO_DIR := mfsdemo
MFSDEMO_SRC := $(wildcard $(MULTIFS_PROJECT_ROOT)/$(MFSDEMO_DIR)/*.cpp)
MFSDEMO_EXE := $(MULTIFS_BIN_DIR)/mfsdemo
MFSDEMO_DEPOPT := -lcrypto

.PHONY: all
all: $(TARGET) $(TARGETSO) $(MFSSRV) $(MFSDEMO_EXE)

.PHONY: mfssrv
mfssrv:	$(MFSSRV)

.PHONY: mfsdemo
mfsdemo: $(MFSDEMO_EXE)

$(TARGET): $(OBJ)
	$(AR) rcsD $@ $(OBJ)

$(TARGETSO): $(OBJ)
	mkdir -p $(MULTIFS_BIN_DIR)
	$(CXX) -m64 -O2 -shared $(CXXFLAGS) $(OBJ) -o $(TARGETSO)

$(MFSSRV):
	mkdir -p $(MULTIFS_BIN_DIR)
	$(CXX) -m64 -O2 $(CXXFLAGS) $(INCLUDE) $(SORTED_MFSSRV_SRC) $(MFSSRV_DEPOPT) -o $(MFSSRV)

$(MFSDEMO_EXE): $(TARGET)
	mkdir -p $(MULTIFS_BIN_DIR)
	$(CXX) -m64 -O2 $(CXXFLAGS) $(INCLUDE) $(MFSDEMO_SRC) $(TARGET) $(MFSDEMO_DEPOPT) -o $(MFSDEMO_EXE)

.PHONY: clean
clean:
	@$(RM) $(OBJ)
	@$(RM) $(TARGET)
	@$(RM) $(TARGETSO)
	@$(RM) $(MFSSRV)
	@$(RM) $(MFSDEMO_EXE)
	@$(RM) -rf $(MULTIFS_BIN_DIR)

.PHONY: rebuild
rebuild:
	$(MAKE) clean
	$(MAKE) all
