/*
 * TrustEdge-CC: Confidential Federated Anomaly Detection
 * OP-TEE Trusted Application Header (ARM TrustZone-A)
 * TA UUID: c4a52140-59f2-43bb-8e31-893080bf0001
 */

#ifndef TRUSTEDGE_TA_H
#define TRUSTEDGE_TA_H

#define TA_TRUSTEDGE_UUID \
    { 0xc4a52140, 0x59f2, 0x43bb, \
        { 0x8e, 0x31, 0x89, 0x30, 0x80, 0xbf, 0x00, 0x01 } }

/* Command IDs for TA Invocation */
#define TA_TRUSTEDGE_CMD_INIT_KEYS          0
#define TA_TRUSTEDGE_CMD_GET_ATTESTATION    1
#define TA_TRUSTEDGE_CMD_TRAIN_IFOREST      2
#define TA_TRUSTEDGE_CMD_INFER_ANOMALY      3
#define TA_TRUSTEDGE_CMD_SEAL_AND_SIGN      4

/* Return Codes */
#define TEE_SUCCESS                         0x00000000
#define TEE_ERROR_GENERIC                   0xFFFF0000
#define TEE_ERROR_BAD_PARAMETERS            0xFFFF0006
#define TEE_ERROR_OUT_OF_MEMORY             0xFFFF000C
#define TEE_ERROR_SECURITY                  0xFFFF000F

#endif /* TRUSTEDGE_TA_H */
