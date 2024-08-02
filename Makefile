#*******************************************************************************
#   Ledger Cardano App
#   (c) 2024 Ledger
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
#*******************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.defines

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME      = "Cardano ADA"

# Application version
APPVERSION_M = 7
APPVERSION_N = 1
APPVERSION_P = 2
APPVERSION   = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOS = icon_ada_nanos.gif
ICON_NANOX = icon_ada_nanox.gif
ICON_NANOSP = icon_ada_nanox.gif
ICON_STAX = icon_ada_stax.gif
ICON_FLEX = icon_ada_flex.gif

# Application allowed derivation curves.
CURVE_APP_LOAD_PARAMS = ed25519

# Application allowed derivation paths.
PATH_APP_LOAD_PARAMS += "44'/1815'" "1852'/1815'" "1853'/1815'" "1854'/1815'" "1855'/1815'" "1694'/1815'"

# Setting to allow building variant applications
VARIANT_PARAM = COIN
VARIANT_VALUES = cardano_ada

DEFINES += RESET_ON_CRASH
# Enabling DEBUG flag will enable PRINTF and disable optimizations
# DEVEL = 1
# DEFINES += HEADLESS

# Enabling debug PRINTF
ifeq ($(DEVEL), 1)
	DEBUG = 1
	DEFINES += DEVEL
endif

########################################
#     Application custom permissions   #
########################################
HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1

########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
DISABLE_STANDARD_APP_FILES = 1
ifeq ($(TARGET_NAME),TARGET_NANOS)
DISABLE_STANDARD_BAGL_UX_FLOW = 1
DISABLE_DEBUG_LEDGER_ASSERT = 1
DISABLE_DEBUG_THROW = 1
endif

SDK_SOURCE_PATH += lib_u2f

##############
#  Compiler  #
##############
## USB U2F
DEFINES += HAVE_U2F HAVE_IO_U2F U2F_PROXY_MAGIC=\"ADA\" USB_SEGMENT_SIZE=64

## Protect stack overflows
DEFINES += HAVE_BOLOS_APP_STACK_CANARY

# restricted features for Nano S
# but not in DEVEL mode where we usually want to test all features with HEADLESS
ifeq ($(TARGET_NAME), TARGET_NANOS)
	ifneq ($(DEVEL), 1)
		APP_XS = 1
	else
		APP_XS = 0
	endif
else
	APP_XS = 0
endif

ifeq ($(APP_XS), 1)
	DEFINES += APP_XS
else
	# features not included in the Nano S app
	DEFINES += APP_FEATURE_OPCERT
	DEFINES += APP_FEATURE_NATIVE_SCRIPT_HASH
	DEFINES += APP_FEATURE_POOL_REGISTRATION
	DEFINES += APP_FEATURE_POOL_RETIREMENT
	DEFINES += APP_FEATURE_BYRON_ADDRESS_DERIVATION
	DEFINES += APP_FEATURE_BYRON_PROTOCOL_MAGIC_CHECK
endif
# always include this, it's important for Plutus users
DEFINES += APP_FEATURE_TOKEN_MINTING

################
#   Analyze    #
################

# part of CI
analyze: clean
	scan-build --use-cc=clang -analyze-headers -enable-checker security -enable-checker unix -enable-checker valist -o scan-build --status-bugs make default

##############
#   Style    #
##############

format:
	astyle --options=.astylerc "src/*.h" "src/*.c" --exclude=src/glyphs.h --exclude=src/glyphs.c --ignore-exclude-errors

##############
#    Size    #
##############

# prints app size, max is about 140K
size: all
	$(GCCPATH)arm-none-eabi-size --format=gnu bin/app.elf

##############
#   Device-specific builds
##############

nanos: clean
	BOLOS_SDK=$(NANOS_SDK) make

nanosp: clean
	BOLOS_SDK=$(NANOSP_SDK) make

nanox: clean
	BOLOS_SDK=$(NANOX_SDK) make

stax: clean
	BOLOS_SDK=$(STAX_SDK) make

# import generic rules from the sdk
include $(BOLOS_SDK)/Makefile.standard_app
