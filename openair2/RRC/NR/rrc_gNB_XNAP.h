/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef RRC_GNB_XNAP_H_
#define RRC_GNB_XNAP_H_

#include "nr_rrc_defs.h"
#include "openair2/COMMON/xnap_messages_types.h"

void rrc_gNB_send_XNAP_HANDOVER_REQUEST(gNB_RRC_INST *rrc,
                                        gNB_RRC_UE_t *UE,
                                        const nr_neighbour_cell_t *neighbour,
                                        byte_array_t hoPrepInfo);

int rrc_gNB_process_XNAP_HANDOVER_REQUEST(gNB_RRC_INST *rrc, xnap_handover_req_t *req);

void rrc_gNB_process_XNAP_HANDOVER_REQ_ACK(gNB_RRC_INST *rrc, const xnap_handover_req_ack_t *msg);

void rrc_gNB_send_XNAP_HANDOVER_REQ_ACK(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE, byte_array_t ho_command);

int rrc_gNB_send_XNAP_SN_STATUS_TRANSFER(gNB_RRC_INST *rrc,
                                          gNB_RRC_UE_t *UE,
                                          const int n_to_mod,
                                          const int *drb_ids,
                                          const e1_pdcp_status_info_t *pdcp_status);

int rrc_gNB_process_XNAP_SN_STATUS_TRANSFER(gNB_RRC_INST *rrc,
                                             instance_t instance,
                                             xnap_sn_status_transfer_t *msg);

void rrc_gNB_send_XNAP_UE_CONTEXT_RELEASE(gNB_RRC_INST *rrc, gNB_RRC_UE_t *UE);

int rrc_gNB_process_XNAP_UE_CONTEXT_RELEASE(gNB_RRC_INST *rrc,
                                              instance_t instance,
                                              xnap_ue_context_release_t *msg);

#endif /* RRC_GNB_XNAP_H_ */
