CFG_TEE_TA_LOG_LEVEL ?= 4
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)

# The UUID for the Trusted Application
BINARY = c4a52140-59f2-43bb-8e31-893080bf0001

-include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

ifeq ($(wildcard $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk), )
clean:
	@rm -rf *.o *.ta
all:
	@echo "Note: To compile with full OP-TEE OS on QEMU, set TA_DEV_KIT_DIR to your optee_os export path."
	@echo "The TrustEdge-CC QEMU Node runner also includes self-contained high-fidelity OP-TEE emulation."
endif
