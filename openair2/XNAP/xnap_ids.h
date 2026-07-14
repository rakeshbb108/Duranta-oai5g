/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* XnAP UE ID management — maps locally-assigned XnAP UE IDs to RRC UE IDs.
 *
 * Source gNB: allocates s_ng_node_ue_xnap_id when sending HandoverRequest;
 *   stores {rrc_ue_id, target_assoc_id} so ACK/Failure can be routed back.
 * Target gNB: allocates t_ng_node_ue_xnap_id when sending HandoverRequestAck;
 *   stores {rrc_ue_id, source_assoc_id} so subsequent messages can be routed. */

#ifndef XNAP_IDS_H_
#define XNAP_IDS_H_

#include <stdbool.h>
#include <stdint.h>
#include "common/platform_types.h"
#include "openair2/COMMON/sctp_messages_types.h"

/* Source-side entry: keyed on s_ng_node_ue_xnap_id */
typedef struct {
  uint32_t     rrc_ue_id;       /* RRC UE ID at source gNB */
  sctp_assoc_t target_assoc_id; /* SCTP association to the target gNB */
} xnap_ue_data_t;

/* Target-side entry: keyed on t_ng_node_ue_xnap_id */
typedef struct {
  uint32_t     rrc_ue_id;       /* RRC UE ID at target gNB */
  sctp_assoc_t source_assoc_id; /* SCTP association back to the source gNB */
} xnap_target_ue_data_t;

/* Call once when the XNAP task starts */
void xnap_init_ue_data(void);

/* Source-side table: keyed on s_ng_node_ue_xnap_id */
uint32_t       xnap_alloc_ue_id(void);
bool           xnap_add_ue_data(uint32_t xnap_ue_id, const xnap_ue_data_t *data);
bool           xnap_exists_ue_data(uint32_t xnap_ue_id);
xnap_ue_data_t xnap_get_ue_data(uint32_t xnap_ue_id);
bool           xnap_remove_ue_data(uint32_t xnap_ue_id);

/* Target-side table: keyed on t_ng_node_ue_xnap_id */
uint32_t              xnap_alloc_target_ue_id(void);
bool                  xnap_add_target_ue_data(uint32_t t_xnap_ue_id, const xnap_target_ue_data_t *data);
bool                  xnap_exists_target_ue_data(uint32_t t_xnap_ue_id);
xnap_target_ue_data_t xnap_get_target_ue_data(uint32_t t_xnap_ue_id);
bool                  xnap_remove_target_ue_data(uint32_t t_xnap_ue_id);

#endif /* XNAP_IDS_H_ */
