/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* XnAP UE ID management — maps locally-assigned XnAP UE IDs to RRC UE IDs.
 *
 * At the source gNB a new xnap_ue_id is allocated when HandoverRequest is
 * sent and stored together with rrc_ue_id so incoming responses (ACK or
 * Failure) can be routed back to the correct RRC UE context. */

#ifndef XNAP_IDS_H_
#define XNAP_IDS_H_

#include <stdbool.h>
#include <stdint.h>
#include "common/platform_types.h"
#include "openair2/COMMON/sctp_messages_types.h"

typedef struct {
  uint32_t     rrc_ue_id;       /* RRC UE ID at source gNB */
  sctp_assoc_t target_assoc_id; /* SCTP association to the target gNB */
} xnap_ue_data_t;

/* Call once when the XNAP task starts */
void xnap_init_ue_data(void);

/* Allocate the next monotonic XnAP UE ID (source role) */
uint32_t xnap_alloc_ue_id(void);

/* Source-side table: keyed on xnap_ue_id (= s_ng_node_ue_xnap_id) */
bool          xnap_add_ue_data(uint32_t xnap_ue_id, const xnap_ue_data_t *data);
bool          xnap_exists_ue_data(uint32_t xnap_ue_id);
xnap_ue_data_t xnap_get_ue_data(uint32_t xnap_ue_id);
bool          xnap_remove_ue_data(uint32_t xnap_ue_id);

#endif /* XNAP_IDS_H_ */
