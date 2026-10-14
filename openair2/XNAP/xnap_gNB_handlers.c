/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xnap_gNB_handlers.h"
#include "xnap_gNB.h"
#include "xnap_common.h"
#include "common/utils/LOG/log.h"
#include "common/utils/ocp_itti/intertask_interface.h"
#include "assertions.h"
#include "xnap_gNB_encoder.h"
#include "xnap_ids.h"
#include "xnap_ho_sm.h"
#include "xnap_ho_timers.h"
#include "lib/xnap_gNB_interface_management.h"
#include "lib/xnap_gNB_mobility_management.h"
#include "aper_decoder.h"
#include "xnap_gNB_itti_messaging.h"

/* Xn peer lost: tell RRC to end the Xn HO of a UE whose association is being purged,
 * through the message it already handles for the equivalent outcome. A target UE already
 * Acked is left alone: it may still arrive over the air and complete via NG Path Switch. */
static void xnap_notify_rrc_ue_peer_lost(const xn_ue_assoc_t *ue, void *ctx)
{
  const instance_t instance = *(const instance_t *)ctx;
  const xnap_cause_t cause = {.type = XNAP_CAUSE_TRANSPORT, .value = XNAP_CAUSE_TRANSPORT_LAYER_TRANSPORT_RESOURCE_UNAVAILABLE};
  MessageDef *msg = NULL;

  if (ue->role == XN_ROLE_SOURCE && ue->src_state == XNAP_HO_SRC_HO_REQ_SENT) {
    msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HANDOVER_PREP_FAILURE);
    XNAP_HANDOVER_PREP_FAILURE(msg) = (xnap_handover_preparation_failure_t){.cause = cause, .rrc_ue_id = ue->rrc_ue_id, .local = true};
  } else if (ue->role == XN_ROLE_SOURCE && ue->src_state == XNAP_HO_SRC_HO_PREPARED) {
    msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HO_RELOCOVERALL_TIMEOUT);
    XNAP_HO_RELOCOVERALL_TIMEOUT(msg) = (xnap_ho_relocoverall_timeout_t){.rrc_ue_id = ue->rrc_ue_id, .peer_lost = true};
  } else if (ue->role == XN_ROLE_TARGET && ue->rrc_ue_id == XN_UE_RRC_ID_UNBOUND) {
    msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HANDOVER_CANCEL);
    XNAP_HANDOVER_CANCEL(msg) = (xnap_handover_cancel_t){.cause = cause, .xn_token = ue->local_xnap_id};
  }

  LOG_W(XNAP, "[gNB %ld] Xn peer lost: dropping xnap_ue_id %u (%s, rrc_ue_id %u)%s\n",
        instance, ue->local_xnap_id, ue->role == XN_ROLE_SOURCE ? "source" : "target", ue->rrc_ue_id,
        msg ? " — notifying RRC" : "");
  if (msg)
    itti_send_msg_to_task(TASK_RRC_GNB, instance, msg);
}

/* Notify RRC of a peer's Xn Setup completion or SCTP-level shutdown. */
void xnap_handle_xn_setup_message(instance_t instance, xnap_peer_t *peer, int sctp_shutdown)
{
  if (sctp_shutdown) {
    if (peer->state == XNAP_PEER_STATE_CONNECTED || peer->state == XNAP_PEER_STATE_WAITING) {
      LOG_W(XNAP, "[gNB %ld] Xn peer assoc_id %d (gNB_id 0x%x) disconnected\n", instance, peer->assoc_id, peer->remote_gnb_id);

      /* release the Xn UE associations using this link before telling RRC the peer is gone */
      xn_ue_purge_assoc(peer->assoc_id, xnap_notify_rrc_ue_peer_lost, &instance);

      /* Notify RRC only if XnSetup had completed because RRC has an entry,
       * WAITING peers never reached RRC so there is nothing to remove. */
      if (peer->state == XNAP_PEER_STATE_CONNECTED && peer->remote_gnb_id != 0) {
        MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_PEER_SHUTDOWN_IND);
        XNAP_PEER_SHUTDOWN_IND(msg).gnb_id = peer->remote_gnb_id;
        itti_send_msg_to_task(TASK_RRC_GNB, instance, msg);
      }
    }
  } else {
    peer->state = XNAP_PEER_STATE_CONNECTED;
    LOG_I(XNAP, "[gNB %ld] Xn peer assoc_id %d (gNB_id 0x%x) setup complete — notifying RRC\n",
          instance, peer->assoc_id, peer->remote_gnb_id);

    /* Notify RRC so it can register this peer as an Xn-capable candidate */
    MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_SETUP_IND);
    XNAP_SETUP_IND(msg).gnb_id   = peer->remote_gnb_id;
    itti_send_msg_to_task(TASK_RRC_GNB, instance, msg);
  }
}

typedef int (*xnap_message_decoded_callback)(instance_t instance,
                                              sctp_assoc_t assoc_id,
                                              uint32_t stream,
                                              xnap_gnb_inst_t *inst,
                                              xnap_peer_t *peer,
                                              XNAP_XnAP_PDU_t *pdu);

static int send_xn_setup_failure(instance_t instance, xnap_peer_t *peer, xnap_cause_group_t type, uint8_t value)
{
  const xnap_setup_failure_t fail = {.cause = {.type = type, .value = value}};
  XNAP_XnAP_PDU_t *fail_pdu = encode_xn_setup_failure(&fail);
  AssertFatal(fail_pdu != NULL, "[gNB %ld] encode_xn_setup_failure() failed\n", instance);
  uint8_t *buffer = NULL;
  uint32_t length = 0;
  int rc = xnap_gNB_encode_pdu(fail_pdu, &buffer, &length);
  ASN_STRUCT_FREE(asn_DEF_XNAP_XnAP_PDU, fail_pdu);
  AssertFatal(rc == 0, "[gNB %ld] xnap_gNB_encode_pdu() failed for XnSetupFailure\n", instance);
  xnap_gNB_itti_send_sctp_data(instance, peer->assoc_id, buffer, length, XNAP_NON_UE_STREAM_ID);
  return -1;
}

static int xnap_gNB_handle_xn_setup_request(instance_t instance,
                                             sctp_assoc_t assoc_id,
                                             uint32_t stream,
                                             xnap_gnb_inst_t *inst,
                                             xnap_peer_t *peer,
                                             XNAP_XnAP_PDU_t *pdu)
{
  UNUSED(assoc_id);
  UNUSED(stream);

  xnap_setup_req_t req = {0};
  if (!decode_xn_setup_request(&req, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode XnSetupRequest from assoc_id %d\n",
          instance, peer->assoc_id);
    return -1;
  }

  peer->remote_gnb_id = req.gNB_id;

  /* Another association to this same remote gNB is already up (e.g. both
   * sides dialled each other simultaneously): keep the existing one, close
   * this redundant association, and don't notify RRC about this one. */
  xnap_peer_t *dup = xnap_get_connected_peer_by_remote_gnb_id(inst, peer->remote_gnb_id, peer->assoc_id);
  if (dup != NULL) {
    LOG_W(XNAP, "[gNB %ld] Duplicate Xn association to gNB_id 0x%x: assoc_id %d already connected, closing redundant assoc_id %d\n",
          instance, peer->remote_gnb_id, dup->assoc_id, peer->assoc_id);
    free_xnap_setup_request(&req);
    xnap_gNB_itti_send_sctp_close_association(instance, peer->assoc_id);
    xnap_remove_peer(inst, peer);
    return -1;
  }

  /* Reject if the peer belongs to a different PLMN — most common failure
   * in misconfigured or cross-operator deployments */
  const plmn_id_t *peer_plmn  = &req.plmn;
  const plmn_id_t *local_plmn = &inst->setup_info.plmn;
  if (peer_plmn->mcc != local_plmn->mcc || peer_plmn->mnc != local_plmn->mnc) {
    LOG_W(XNAP, "[gNB %ld] XnSetupRequest from assoc_id %d (gNB_id 0x%x): "
          "PLMN mismatch (peer MCC/MNC %u/%u, local %u/%u) — rejecting\n",
          instance, peer->assoc_id, peer->remote_gnb_id,
          peer_plmn->mcc, peer_plmn->mnc, local_plmn->mcc, local_plmn->mnc);
    free_xnap_setup_request(&req);
    return send_xn_setup_failure(instance, peer, XNAP_CAUSE_MISC, XNAP_CAUSE_MISC_O_AND_M_INTERVENTION);
  }

  free_xnap_setup_request(&req);

  LOG_I(XNAP, "[gNB %ld] XnSetupRequest from peer assoc_id %d (gNB_id 0x%x) — sending XnSetupResponse\n",
        instance, peer->assoc_id, peer->remote_gnb_id);

  xnap_setup_resp_t resp = {
    .gNB_id = inst->setup_info.gNB_id,
    .plmn = inst->setup_info.plmn,
    .num_tai = inst->setup_info.num_tai,
    .tai_support = inst->setup_info.tai_support,
  };

  XNAP_XnAP_PDU_t *resp_pdu = encode_xn_setup_response(&resp);
  AssertFatal(resp_pdu != NULL, "[gNB %ld] encode_xn_setup_response() failed\n", instance);

  uint8_t *buffer = NULL;
  uint32_t length = 0;
  int rc = xnap_gNB_encode_pdu(resp_pdu, &buffer, &length);
  ASN_STRUCT_FREE(asn_DEF_XNAP_XnAP_PDU, resp_pdu);
  AssertFatal(rc == 0, "[gNB %ld] xnap_gNB_encode_pdu() failed for XnSetupResponse\n", instance);

  xnap_gNB_itti_send_sctp_data(instance, peer->assoc_id, buffer, length, XNAP_NON_UE_STREAM_ID);

  /* Xn interface is now active from our side — notify RRC */
  xnap_handle_xn_setup_message(instance, peer, 0);
  return 0;
}

static int xnap_gNB_handle_xn_setup_response(instance_t instance,
                                              sctp_assoc_t assoc_id,
                                              uint32_t stream,
                                              xnap_gnb_inst_t *inst,
                                              xnap_peer_t *peer,
                                              XNAP_XnAP_PDU_t *pdu)
{
  UNUSED(assoc_id);
  UNUSED(stream);

  xnap_setup_resp_t resp = {0};
  if (!decode_xn_setup_response(&resp, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode XnSetupResponse from assoc_id %d\n",
          instance, peer->assoc_id);
    return -1;
  }

  peer->remote_gnb_id = resp.gNB_id;
  free_xnap_setup_response(&resp);

  /* Another association to this same remote gNB is already up (e.g. both
   * sides dialled each other simultaneously): keep the existing one, close
   * this redundant association, and don't notify RRC about this one. */
  xnap_peer_t *dup = xnap_get_connected_peer_by_remote_gnb_id(inst, peer->remote_gnb_id, peer->assoc_id);
  if (dup != NULL) {
    LOG_W(XNAP, "[gNB %ld] Duplicate Xn association to gNB_id 0x%x: assoc_id %d already connected, closing redundant assoc_id %d\n",
          instance, peer->remote_gnb_id, dup->assoc_id, peer->assoc_id);
    xnap_gNB_itti_send_sctp_close_association(instance, peer->assoc_id);
    xnap_remove_peer(inst, peer);
    return -1;
  }

  xnap_handle_xn_setup_message(instance, peer, 0);
  return 0;
}

static const char *xnap_cause_group2str(xnap_cause_group_t t)
{
  switch (t) {
    case XNAP_CAUSE_RADIO_NETWORK: return "radioNetwork";
    case XNAP_CAUSE_TRANSPORT:     return "transport";
    case XNAP_CAUSE_PROTOCOL:      return "protocol";
    case XNAP_CAUSE_MISC:          return "misc";
    default:                       return "unknown";
  }
}

static int xnap_gNB_handle_xn_setup_failure(instance_t instance,
                                             sctp_assoc_t assoc_id,
                                             uint32_t stream,
                                             xnap_gnb_inst_t *inst,
                                             xnap_peer_t *peer,
                                             XNAP_XnAP_PDU_t *pdu)
{
  UNUSED(assoc_id);
  UNUSED(stream);

  xnap_setup_failure_t fail = {0};
  if (!decode_xn_setup_failure(&fail, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode XnSetupFailure from assoc_id %d\n",
          instance, peer->assoc_id);
    return -1;
  }

  LOG_W(XNAP, "[gNB %ld] XnSetupFailure from peer assoc_id %d (gNB_id 0x%x): "
        "cause %s value=%d — Xn interface not established\n",
        instance, peer->assoc_id, peer->remote_gnb_id,
        xnap_cause_group2str(fail.cause.type), fail.cause.value);

  xnap_remove_peer(inst, peer);

  free_xnap_setup_failure(&fail);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Handover Preparation handlers                                        */
/* ------------------------------------------------------------------ */

/* Source-side entry addressed by an incoming PDU's local (source) XnAP ID, on the peer it came from */
static xn_ue_assoc_t *xnap_get_source_ue(sctp_assoc_t assoc_id, uint32_t s_xnap_ue_id)
{
  xn_ue_assoc_t *ue = xn_ue_get_by_local(s_xnap_ue_id);
  if (ue == NULL || ue->role != XN_ROLE_SOURCE || ue->assoc_id != assoc_id)
    return NULL;
  return ue;
}

/* Source gNB: receives HandoverRequestAck from target — store the target XnAP ID, forward to RRC */
static int xnap_gNB_handle_handover_request_acknowledge(instance_t instance,
                                                         sctp_assoc_t assoc_id,
                                                         uint32_t stream,
                                                         xnap_gnb_inst_t *inst,
                                                         xnap_peer_t *peer,
                                                         XNAP_XnAP_PDU_t *pdu)
{
  (void)stream;
  (void)peer;
  LOG_I(XNAP, "[gNB %ld] Received HandoverRequestAck from assoc_id %d\n", instance, assoc_id);

  xnap_handover_req_ack_t ack = {0};
  if (!decode_xnap_handover_request_acknowledge(&ack, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode HandoverRequestAck from assoc_id %d\n",
          instance, assoc_id);
    return -1;
  }

  xn_ue_assoc_t *ue = xnap_get_source_ue(assoc_id, ack.s_ng_node_ue_xnap_id);
  if (ue == NULL) {
    LOG_E(XNAP, "[gNB %ld] HandoverRequestAck: unknown s_xnap_ue_id %u on assoc_id %d — dropping\n",
          instance, ack.s_ng_node_ue_xnap_id, assoc_id);
    free_xnap_handover_request_acknowledge(&ack);
    return -1;
  }
  xnap_ho_src_result_t r = xnap_ho_src_transition(ue->src_state, XNAP_HO_SRC_EV_HANDOVER_REQUEST_ACK);
  if (r.action == XNAP_HO_SRC_ACT_ILLEGAL) {
    free_xnap_handover_request_acknowledge(&ack);
    return -1;
  }
  ue->remote_xnap_id = ack.t_ng_node_ue_xnap_id;
  ue->remote_valid = true;
  ue->src_state = r.next_state;
  xnap_ho_src_set_relocoverall_start(&ue->timer_marks, xnap_ho_timers_now());

  ack.rrc_ue_id = ue->rrc_ue_id;

  MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HANDOVER_REQ_ACK);
  XNAP_HANDOVER_REQ_ACK(msg) = ack;

  LOG_I(XNAP, "[gNB %ld] HandoverRequestAck: rrc_ue_id %u s_xnap_ue_id %u t_xnap_ue_id %u — notifying RRC\n",
        instance, ue->rrc_ue_id, ack.s_ng_node_ue_xnap_id, ack.t_ng_node_ue_xnap_id);

  itti_send_msg_to_task(TASK_RRC_GNB, instance, msg);
  return 0;
}

/* Source gNB: receives HandoverPreparationFailure from target — drop the UE
 * association (the HO preparation is over) and forward to RRC */
static int xnap_gNB_handle_handover_prep_failure(instance_t instance,
                                                  sctp_assoc_t assoc_id,
                                                  uint32_t stream,
                                                  xnap_gnb_inst_t *inst,
                                                  xnap_peer_t *peer,
                                                  XNAP_XnAP_PDU_t *pdu)
{
  (void)stream;
  (void)peer;
  LOG_I(XNAP, "[gNB %ld] Received HandoverPreparationFailure from assoc_id %d\n", instance, assoc_id);

  xnap_handover_preparation_failure_t fail = {0};
  if (!decode_xnap_handover_preparation_failure(&fail, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode HandoverPreparationFailure from assoc_id %d\n",
          instance, assoc_id);
    return -1;
  }

  xn_ue_assoc_t *ue = xnap_get_source_ue(assoc_id, fail.s_ng_node_ue_xnap_id);
  if (ue == NULL) {
    LOG_E(XNAP, "[gNB %ld] HandoverPreparationFailure: unknown s_xnap_ue_id %u on assoc_id %d — dropping\n",
          instance, fail.s_ng_node_ue_xnap_id, assoc_id);
    return -1;
  }
  xnap_ho_src_result_t r = xnap_ho_src_transition(ue->src_state, XNAP_HO_SRC_EV_HANDOVER_PREP_FAILURE);
  if (r.action == XNAP_HO_SRC_ACT_ILLEGAL)
    return -1;

  fail.rrc_ue_id = ue->rrc_ue_id;
  xn_ue_remove(ue->local_xnap_id);

  LOG_W(XNAP, "[gNB %ld] HandoverPreparationFailure: rrc_ue_id %u s_xnap_ue_id %u cause group %d value %d — notifying RRC\n",
        instance, fail.rrc_ue_id, fail.s_ng_node_ue_xnap_id, fail.cause.type, fail.cause.value);

  MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HANDOVER_PREP_FAILURE);
  XNAP_HANDOVER_PREP_FAILURE(msg) = fail;
  itti_send_msg_to_task(TASK_RRC_GNB, instance, msg);
  return 0;
}

/* Target gNB: receives HandoverRequest from source — allocate the target XnAP ID,
 * create a pending entry and forward to RRC with the ID as opaque xn_token */
static int xnap_gNB_handle_handover_request(instance_t instance,
                                                 sctp_assoc_t assoc_id,
                                                 uint32_t stream,
                                                 xnap_gnb_inst_t *inst,
                                                 xnap_peer_t *peer,
                                                 XNAP_XnAP_PDU_t *pdu)
{
  (void)stream;
  (void)peer;
  LOG_I(XNAP, "[gNB %ld] Received HandoverRequest from assoc_id %d\n", instance, assoc_id);

  MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HANDOVER_REQ);
  xnap_handover_req_t *req = &XNAP_HANDOVER_REQ(msg);

  if (!decode_xnap_handover_request(req, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode HandoverRequest from assoc_id %d\n",
          instance, assoc_id);
    itti_free(TASK_XNAP, msg);
    return -1;
  }

  if (xn_ue_get_target_by_remote(assoc_id, req->s_ng_node_ue_xnap_id) != NULL) {
    LOG_W(XNAP, "[gNB %ld] HandoverRequest: s_xnap_ue_id %u on assoc_id %d already in progress — dropping\n",
          instance, req->s_ng_node_ue_xnap_id, assoc_id);
    free_xnap_handover_request(req);
    itti_free(TASK_XNAP, msg);
    return -1;
  }

  xnap_ho_tgt_result_t r = xnap_ho_tgt_transition(XNAP_HO_TGT_XN_READY, XNAP_HO_TGT_EV_HANDOVER_REQUEST);
  xn_ue_assoc_t ue = {.local_xnap_id = xn_ue_alloc_local_id(),
                      .remote_xnap_id = req->s_ng_node_ue_xnap_id,
                      .remote_valid = true,
                      .rrc_ue_id = XN_UE_RRC_ID_UNBOUND,
                      .role = XN_ROLE_TARGET,
                      .assoc_id = assoc_id,
                      .tgt_state = r.next_state};
  bool ok = xn_ue_add(&ue);
  AssertFatal(ok, "[gNB %ld] Failed to store UE data for xnap_ue_id %u\n", instance, ue.local_xnap_id);
  req->xn_token = ue.local_xnap_id;

  LOG_I(XNAP, "[gNB %ld] HandoverRequest: s_xnap_ue_id %u -> t_xnap_ue_id %u (pending admission) — notifying RRC\n",
        instance, ue.remote_xnap_id, ue.local_xnap_id);

  itti_send_msg_to_task(TASK_RRC_GNB, instance, msg);
  return 0;
}

/* ------------------------------------------------------------------ */
/* SN Status Transfer handler                                           */
/* ------------------------------------------------------------------ */

/* Target gNB: receives SN Status Transfer from source — resolve rrc_ue_id and forward to RRC */
static int xnap_gNB_handle_sn_status_transfer(instance_t instance,
                                               sctp_assoc_t assoc_id,
                                               uint32_t stream,
                                               xnap_gnb_inst_t *inst,
                                               xnap_peer_t *peer,
                                               XNAP_XnAP_PDU_t *pdu)
{
  (void)stream;
  (void)peer;
  LOG_I(XNAP, "[gNB %ld] Received SN Status Transfer from assoc_id %d\n", instance, assoc_id);

  xnap_sn_status_transfer_t msg = {0};
  if (!decode_xnap_sn_status_transfer(&msg, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode SN Status Transfer from assoc_id %d\n",
          instance, assoc_id);
    return -1;
  }

  const xn_ue_assoc_t *ue = xn_ue_get_by_local(msg.t_ng_node_ue_xnap_id);
  if (ue == NULL || ue->role != XN_ROLE_TARGET || ue->assoc_id != assoc_id || ue->rrc_ue_id == XN_UE_RRC_ID_UNBOUND
      || ue->remote_xnap_id != msg.s_ng_node_ue_xnap_id) {
    LOG_E(XNAP, "[gNB %ld] SN Status Transfer: unknown s_xnap_ue_id %u / t_xnap_ue_id %u on assoc_id %d — dropping\n",
          instance, msg.s_ng_node_ue_xnap_id, msg.t_ng_node_ue_xnap_id, assoc_id);
    return -1;
  }
  msg.rrc_ue_id = ue->rrc_ue_id;

  LOG_I(XNAP, "[gNB %ld] SN Status Transfer: s_xnap_ue_id %u t_xnap_ue_id %u rrc_ue_id %u nb_drb %u\n",
        instance, msg.s_ng_node_ue_xnap_id, msg.t_ng_node_ue_xnap_id, msg.rrc_ue_id, msg.ran_status.nb_drb);

  MessageDef *itti_msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_SN_STATUS_TRANSFER);
  XNAP_SN_STATUS_TRANSFER(itti_msg) = msg;
  itti_send_msg_to_task(TASK_RRC_GNB, instance, itti_msg);
  return 0;
}

/* ------------------------------------------------------------------ */
/* UE Context Release handler                                           */
/* ------------------------------------------------------------------ */

/* Source gNB: receives UE Context Release from target — drop the UE association, forward to RRC */
static int xnap_gNB_handle_ue_context_release(instance_t instance,
                                               sctp_assoc_t assoc_id,
                                               uint32_t stream,
                                               xnap_gnb_inst_t *inst,
                                               xnap_peer_t *peer,
                                               XNAP_XnAP_PDU_t *pdu)
{
  (void)stream;
  (void)peer;
  LOG_I(XNAP, "[gNB %ld] Received UE Context Release from assoc_id %d\n", instance, assoc_id);

  xnap_ue_context_release_t msg = {0};
  if (!decode_xnap_ue_context_release(&msg, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode UE Context Release from assoc_id %d\n",
          instance, assoc_id);
    return -1;
  }

  xn_ue_assoc_t *ue = xnap_get_source_ue(assoc_id, msg.s_ng_node_ue_xnap_id);
  if (ue == NULL || !ue->remote_valid || ue->remote_xnap_id != msg.t_ng_node_ue_xnap_id) {
    LOG_W(XNAP, "[gNB %ld] UE Context Release: unknown s_xnap_ue_id %u / t_xnap_ue_id %u on assoc_id %d — dropping\n",
          instance, msg.s_ng_node_ue_xnap_id, msg.t_ng_node_ue_xnap_id, assoc_id);
    return -1;
  }
  xnap_ho_src_result_t r = xnap_ho_src_transition(ue->src_state, XNAP_HO_SRC_EV_UE_CONTEXT_RELEASE);
  if (r.action == XNAP_HO_SRC_ACT_ILLEGAL)
    return -1;

  msg.rrc_ue_id = ue->rrc_ue_id;
  xn_ue_remove(ue->local_xnap_id);

  LOG_I(XNAP, "[gNB %ld] UE Context Release: s_xnap_ue_id %u t_xnap_ue_id %u rrc_ue_id %u — notifying RRC\n",
        instance, msg.s_ng_node_ue_xnap_id, msg.t_ng_node_ue_xnap_id, msg.rrc_ue_id);

  MessageDef *itti_msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_UE_CONTEXT_RELEASE);
  XNAP_UE_CONTEXT_RELEASE(itti_msg) = msg;
  itti_send_msg_to_task(TASK_RRC_GNB, instance, itti_msg);
  return 0;
}

/* ------------------------------------------------------------------ */
/* Handover Cancel handler                                              */
/* ------------------------------------------------------------------ */

/* Target gNB: receives HandoverCancel from source — release the reserved UE association
 * (Class 2, no reply) and tell RRC: by rrc_ue_id after the Ack, by xn_token before it */
static int xnap_gNB_handle_handover_cancel(instance_t instance,
                                            sctp_assoc_t assoc_id,
                                            uint32_t stream,
                                            xnap_gnb_inst_t *inst,
                                            xnap_peer_t *peer,
                                            XNAP_XnAP_PDU_t *pdu)
{
  (void)stream;
  (void)peer;
  LOG_I(XNAP, "[gNB %ld] Received HandoverCancel from assoc_id %d\n", instance, assoc_id);

  xnap_handover_cancel_t msg = {0};
  if (!decode_xnap_handover_cancel(&msg, pdu)) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode HandoverCancel from assoc_id %d\n",
          instance, assoc_id);
    return -1;
  }

  xn_ue_assoc_t *ue = xn_ue_get_target_by_remote(assoc_id, msg.s_ng_node_ue_xnap_id);
  if (ue == NULL) {
    LOG_W(XNAP, "[gNB %ld] HandoverCancel: unknown s_xnap_ue_id %u on assoc_id %d — dropping\n",
          instance, msg.s_ng_node_ue_xnap_id, assoc_id);
    return -1;
  }
  xnap_ho_tgt_result_t r = xnap_ho_tgt_transition(ue->tgt_state, XNAP_HO_TGT_EV_HANDOVER_CANCEL);
  if (r.action == XNAP_HO_TGT_ACT_ILLEGAL) {
    LOG_W(XNAP, "[gNB %ld] HandoverCancel: stale/late cancel for t_xnap_ue_id %u (sm_state %d) — dropping\n",
          instance, ue->local_xnap_id, ue->tgt_state);
    return -1;
  }

  if (ue->rrc_ue_id != XN_UE_RRC_ID_UNBOUND)
    msg.rrc_ue_id = ue->rrc_ue_id;
  else
    msg.xn_token = ue->local_xnap_id;
  LOG_W(XNAP, "[gNB %ld] HandoverCancel: s_xnap_ue_id %u t_xnap_ue_id %u rrc_ue_id %u — notifying RRC\n",
        instance, msg.s_ng_node_ue_xnap_id, ue->local_xnap_id, ue->rrc_ue_id);
  xn_ue_remove(ue->local_xnap_id);

  MessageDef *itti_msg = itti_alloc_new_message(TASK_XNAP, instance, XNAP_HANDOVER_CANCEL);
  XNAP_HANDOVER_CANCEL(itti_msg) = msg;
  itti_send_msg_to_task(TASK_RRC_GNB, instance, itti_msg);
  return 0;
}

/* Callback table
 * Indexed by [procedureCode][direction-1]
 * where direction is:  0 = initiatingMessage, 1 = successfulOutcome, 2 = unsuccessfulOutcome
 * Procedure codes taken from XNAP_ProcedureCode.h (TS 38.423 v16.2.0)
 */
static const xnap_message_decoded_callback xnap_messages_callback[][3] = {
  {xnap_gNB_handle_handover_request, xnap_gNB_handle_handover_request_acknowledge, xnap_gNB_handle_handover_prep_failure}, /*  0 handoverPreparation */
  {xnap_gNB_handle_sn_status_transfer, 0, 0}, /*  1 sNStatusTransfer */
  {xnap_gNB_handle_handover_cancel, 0, 0}, /*  2 handoverCancel */
  {0, 0, 0}, /*  3 retrieveUEContext */
  {0, 0, 0}, /*  4 rANPaging */
  {0, 0, 0}, /*  5 xnUAddressIndication */
  {xnap_gNB_handle_ue_context_release, 0, 0}, /*  6 uEContextRelease */
  {0, 0, 0}, /*  7 sNGRANnodeAdditionPreparation */
  {0, 0, 0}, /*  8 sNGRANnodeReconfigurationCompletion */
  {0, 0, 0}, /*  9 mNGRANnodeinitiatedSNGRANnodeModificationPrep */
  {0, 0, 0}, /* 10 sNGRANnodeinitiatedSNGRANnodeModificationPrep */
  {0, 0, 0}, /* 11 mNGRANnodeinitiatedSNGRANnodeRelease */
  {0, 0, 0}, /* 12 sNGRANnodeinitiatedSNGRANnodeRelease */
  {0, 0, 0}, /* 13 sNGRANnodeCounterCheck */
  {0, 0, 0}, /* 14 sNGRANnodeChange */
  {0, 0, 0}, /* 15 rRCTransfer */
  {0, 0, 0}, /* 16 xnRemoval */
  {xnap_gNB_handle_xn_setup_request, xnap_gNB_handle_xn_setup_response, xnap_gNB_handle_xn_setup_failure}, /* 17 xnSetup */
  {0, 0, 0}, /* 18 nGRANnodeConfigurationUpdate */
  {0, 0, 0}, /* 19 cellActivation */
  {0, 0, 0}, /* 20 reset */
  {0, 0, 0}, /* 21 errorIndication */
  {0, 0, 0}, /* 22 privateMessage */
  {0, 0, 0}, /* 23 notificationControl */
  {0, 0, 0}, /* 24 activityNotification */
  {0, 0, 0}, /* 25 e_UTRA_NR_CellResourceCoordination */
  {0, 0, 0}, /* 26 secondaryRATDataUsageReport */
  {0, 0, 0}, /* 27 deactivateTrace */
  {0, 0, 0}, /* 28 traceStart */
  {0, 0, 0}, /* 29 handoverSuccess */
  {0, 0, 0}, /* 30 conditionalHandoverCancel */
  {0, 0, 0}, /* 31 earlyStatusTransfer */
  {0, 0, 0}, /* 32 failureIndication */
  {0, 0, 0}, /* 33 handoverReport */
  {0, 0, 0}, /* 34 resourceStatusReportingInitiation */
  {0, 0, 0}, /* 35 resourceStatusReporting */
  {0, 0, 0}, /* 36 mobilitySettingsChange */
  {0, 0, 0}, /* 37 accessAndMobilityIndication */
};

static const char *xnap_direction2str(int dir)
{
  static const char *const s[] = {"", "initiatingMessage", "successfulOutcome", "unsuccessfulOutcome"};
  return (dir >= 0 && dir <= 3) ? s[dir] : "unknown";
}

static XNAP_XnAP_PDU_t *xnap_gNB_decode_pdu(const uint8_t *const buf, uint32_t len)
{
  DevAssert(buf != NULL);
  asn_codec_ctx_t st = {.max_stack_size = 100 * 1000};
  XNAP_XnAP_PDU_t *pdu = NULL;
  asn_dec_rval_t dec = aper_decode(&st, &asn_DEF_XNAP_XnAP_PDU, (void **)&pdu, buf, len, 0, 0);

  if (LOG_DEBUGFLAG(DEBUG_ASN1)) {
    LOG_E(XNAP, "----------------- ASN1 DECODER PRINT START----------------- \n");
    xer_fprint(stdout, &asn_DEF_XNAP_XnAP_PDU, pdu);
    LOG_E(XNAP, "----------------- ASN1 DECODER PRINT END ----------------- \n");
  }

  return dec.code == RC_OK ? pdu : NULL;
}

int xnap_gNB_handle_message(instance_t instance, sctp_assoc_t assoc_id, uint32_t stream, const uint8_t *buf, uint32_t len)
{
  xnap_gnb_inst_t *inst = xnap_get_inst(instance);
  AssertFatal(inst != NULL, "Xn instance %ld not found\n", instance);

  xnap_peer_t *peer = xnap_get_peer_by_assoc(inst, assoc_id);
  if (peer == NULL) {
    LOG_E(XNAP, "[gNB %ld] xnap_gNB_handle_message: no peer for assoc_id %d\n", instance, assoc_id);
    return -1;
  }

  XNAP_XnAP_PDU_t *pdu = xnap_gNB_decode_pdu(buf, len);
  if (pdu == NULL) {
    LOG_E(XNAP, "[gNB %ld] Failed to decode XnAP PDU from assoc_id %d\n", instance, assoc_id);
    return -1;
  }

  /* Checking procedure Code and direction of message */
  if (pdu->choice.initiatingMessage->procedureCode >= (long)(sizeof(xnap_messages_callback) / (3 * sizeof(xnap_message_decoded_callback)))
      || pdu->present > XNAP_XnAP_PDU_PR_unsuccessfulOutcome) {
    LOG_E(XNAP,
          "[gNB %ld] [SCTP %d] Either procedureCode %ld or direction %d exceed expected\n",
          instance,
          assoc_id,
          pdu->choice.initiatingMessage->procedureCode,
          pdu->present);
    ASN_STRUCT_FREE(asn_DEF_XNAP_XnAP_PDU, pdu);
    return -1;
  }

  int ret;
  if (xnap_messages_callback[pdu->choice.initiatingMessage->procedureCode][pdu->present - 1] == NULL) {
    // No handler present. This can mean not implemented or no procedure for this direction.
    LOG_W(XNAP,
          "[gNB %ld] [SCTP %d] No handler for procedureCode %ld in %s\n",
          instance,
          assoc_id,
          pdu->choice.initiatingMessage->procedureCode,
          xnap_direction2str(pdu->present));
    ret = 0;
  } else {
    /* Calling the right handler */
    LOG_D(XNAP, "Calling handler with instance %ld\n", instance);
    ret = (*xnap_messages_callback[pdu->choice.initiatingMessage->procedureCode][pdu->present - 1])(instance, assoc_id, stream, inst, peer, pdu);
  }

  ASN_STRUCT_FREE(asn_DEF_XNAP_XnAP_PDU, pdu);
  return ret;
}
