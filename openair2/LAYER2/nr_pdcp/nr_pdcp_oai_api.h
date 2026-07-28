/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef NR_PDCP_OAI_API_H
#define NR_PDCP_OAI_API_H

#include <assertions.h>
#include <stdbool.h>
#include <stdint.h>
#include "NR_DRB-ToAddModList.h"
#include "NR_PDCP-Config.h"
#include "NR_SRB-ToAddModList.h"
#include "nr_pdcp/nr_pdcp_entity.h"
#include "nr_pdcp/nr_pdcp_integrity_data.h"
#include "nr_pdcp_ue_manager.h"
struct NR_DRB_ToAddMod;
struct NR_SRB_ToAddMod;
struct sdap_configuration_s;

void nr_pdcp_layer_init(void);

bool nr_pdcp_data_ind(const protocol_ctxt_t *const ctxt_pP,
                      const srb_flag_t srb_flagP,
                      const rb_id_t rb_id,
                      const sdu_size_t sdu_buffer_size,
                      uint8_t *const sdu_buffer);

void nr_pdcp_add_srbs(eNB_flag_t enb_flag,
                      ue_id_t UEid,
                      NR_SRB_ToAddModList_t *const srb2add_list,
                      const nr_pdcp_entity_security_keys_and_algos_t *security_parameters);

void nr_pdcp_add_drb(int is_gnb,
                     const ue_id_t UEid,
                     const NR_PDCP_Config_t *pdcp,
                     const struct sdap_configuration_s *sdap,
                     const nr_pdcp_entity_security_keys_and_algos_t *security_parameters);

void nr_pdcp_remove_UE(ue_id_t ue_id);
void nr_pdcp_reestablishment(ue_id_t ue_id,
                             int rb_id,
                             bool srb_flag,
                             const nr_pdcp_entity_security_keys_and_algos_t *security_parameters);

void nr_pdcp_suspend_srb(ue_id_t ue_id, int srb_id);
void nr_pdcp_suspend_drb(ue_id_t ue_id, int drb_id);
void nr_pdcp_reconfigure_srb(ue_id_t ue_id, int srb_id, long t_Reordering);
void nr_pdcp_reconfigure_drb(ue_id_t ue_id, int drb_id, NR_PDCP_Config_t *pdcp_config);
void nr_pdcp_release_srb(ue_id_t ue_id, int srb_id);
void nr_pdcp_release_drb(ue_id_t ue_id, int drb_id);
int nr_pdcp_get_drb_ids_for_pdusession(ue_id_t ue_id, long pdusession_id, int *drb_ids);

void add_srb(int is_gnb,
             ue_id_t UEid,
             struct NR_SRB_ToAddMod *s,
             const nr_pdcp_entity_security_keys_and_algos_t *security_parameters);

void nr_pdcp_config_set_security(ue_id_t ue_id,
                                 rb_id_t rb_id,
                                 bool is_srb,
                                 const nr_pdcp_entity_security_keys_and_algos_t *parameters);

bool nr_pdcp_check_integrity_srb(ue_id_t ue_id,
                                 int srb_id,
                                 const uint8_t *msg,
                                 int msg_size,
                                 const nr_pdcp_integrity_data_t *msg_integrity);

bool cu_f1u_data_req(protocol_ctxt_t  *ctxt_pP,
                     const srb_flag_t srb_flagP,
                     const rb_id_t rb_id,
                     const mui_t muiP,
                     const confirm_t confirmP,
                     const sdu_size_t sdu_buffer_size,
                     unsigned char *const sdu_buffer,
                     const pdcp_transmission_mode_t mode,
                     const uint32_t *const sourceL2Id,
                     const uint32_t *const destinationL2Id);

typedef void (*deliver_pdu)(void *data, ue_id_t ue_id, int srb_id,
                            char *buf, int size, int sdu_id);
/* default implementation of deliver_pdu */
void deliver_pdu_srb_rlc(void *data, ue_id_t ue_id, int srb_id, char *buf, int size, int sdu_id);
bool nr_pdcp_data_req_srb(ue_id_t ue_id,
                          const rb_id_t rb_id,
                          const mui_t muiP,
                          const sdu_size_t sdu_buffer_size,
                          unsigned char *const sdu_buffer,
                          deliver_pdu deliver_cb,
                          void *data);
bool nr_pdcp_data_req_drb(protocol_ctxt_t *ctxt_pP,
                          const srb_flag_t srb_flagP,
                          const rb_id_t rb_id,
                          const mui_t muiP,
                          const confirm_t confirmP,
                          const sdu_size_t sdu_buffer_size,
                          unsigned char *const sdu_buffer,
                          const pdcp_transmission_mode_t mode,
                          const uint32_t *const sourceL2Id,
                          const uint32_t *const destinationL2Id);

nr_pdcp_ue_manager_t *nr_pdcp_sdap_get_ue_manager();

int nr_pdcp_get_num_ues(ue_id_t *ue_list, int len);

bool nr_pdcp_get_statistics(ue_id_t ue_id, int srb_flag, int rb_id, nr_pdcp_statistics_t *out);

void nr_pdcp_count_update(ue_id_t ue_id,
                          rb_id_t drb_id,
                          nr_pdcp_count_t dl_count,
                          nr_pdcp_count_t ul_count,
                          int sn_size);

void nr_pdcp_get_drb_count_values(ue_id_t ue_id, rb_id_t rb_id, nr_pdcp_count_t *ul_count, nr_pdcp_count_t *dl_count);

void nr_pdcp_entity_ack_sdu(ue_id_t ue_id, rb_id_t rb_id, uint32_t count);

/* Xn HO DL data forwarding (TS 38.300 / 29.281 5.2.2.2, 5.2.2.2A) */
bool nr_pdcp_data_req_drb_with_sn(ue_id_t ue_id, int pdusession_id, uint8_t qfi, uint32_t pdcp_sn, const uint8_t *buf, int size);
void nr_pdcp_drain_and_forward_pending_sdus(instance_t n3inst, ue_id_t ue_id, int pdusession_id);

/* TS 38.425 DDDS flow control (Xn HO) */
int nr_pdcp_get_highest_tx_sn(ue_id_t ue_id, rb_id_t rb_id);
int nr_pdcp_get_highest_delivered_sn(ue_id_t ue_id, rb_id_t rb_id);
/* enqueue a deferred re-drain (called from the GTP-U RX thread when a DDDS lifts credit) */
void nr_pdcp_schedule_redrain(instance_t n3inst, ue_id_t ue_id, int pdusession_id);
/* service pending re-drains (called from the PDCP timer thread, outside the manager lock) */
void nr_pdcp_service_redrain_queue(void);

#endif /* NR_PDCP_OAI_API_H */
