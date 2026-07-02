/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <string.h>
#include "xnap_gNB.h"
#include "xnap_common.h"
#include "xnap_default_values.h"
#include "lib/xnap_gNB_interface_management.h"
#include "xnap_gNB_encoder.h"
#include "common/utils/LOG/log.h"
#include "common/platform_types.h"
#include "common/utils/ocp_itti/intertask_interface.h"
#include "openair2/COMMON/sctp_messages_types.h"
#include "assertions.h"

static void xnap_gNB_itti_send_sctp_data(instance_t instance,
                                          sctp_assoc_t assoc_id,
                                          uint8_t *buffer,
                                          uint32_t length,
                                          uint16_t stream)
{
  MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, SCTP_DATA_REQ);
  sctp_data_req_t *req = &msg->ittiMsg.sctp_data_req;
  req->assoc_id      = assoc_id;
  req->buffer        = buffer;
  req->buffer_length = length;
  req->stream        = stream;
  itti_send_msg_to_task(TASK_SCTP, instance, msg);
}

static void xnap_gNB_generate_xn_setup_request(instance_t instance, xnap_gnb_inst_t *inst, xnap_peer_t *peer)
{
  /* xnap_setup_req_t and xnap_setup_info_t share the same layout */
  const xnap_setup_req_t *req = (const xnap_setup_req_t *)&inst->setup_info;

  XNAP_XnAP_PDU_t *pdu = encode_xn_setup_request(req);
  AssertFatal(pdu != NULL, "[gNB %ld] encode_xn_setup_request() failed\n", instance);

  uint8_t *buffer = NULL;
  uint32_t length = 0;
  int rc = xnap_gNB_encode_pdu(pdu, &buffer, &length);
  ASN_STRUCT_FREE(asn_DEF_XNAP_XnAP_PDU, pdu);
  AssertFatal(rc == 0, "[gNB %ld] xnap_gNB_encode_pdu() failed for XnSetupRequest\n", instance);

  LOG_I(XNAP, "[gNB %ld] Sending XnSetupRequest to peer assoc_id %d (%u bytes)\n",
        instance, peer->assoc_id, length);

  /* XnSetup is non-UE-associated signalling — always stream 0 */
  xnap_gNB_itti_send_sctp_data(instance, peer->assoc_id, buffer, length, XNAP_NONUE_STREAM_ID);
}

/* Phase 1: bind local SCTP listener socket */
static void xnap_gNB_handle_register_gnb(instance_t instance, xnap_register_gnb_req_t *req)
{
  createXninst(instance, &req->setup_info, &req->net_config);

  xnap_gnb_inst_t *inst = getCxtXn(instance);
  AssertFatal(inst != NULL, "Xn instance %ld not found after creation\n", instance);

  const char *local_ip = inst->net_config.gnb_xn_interface_ip_address;
  size_t addr_len = strlen(local_ip) + 1;

  MessageDef *msg = itti_alloc_new_message_sized(TASK_XNAP, instance, SCTP_INIT_MSG_MULTI_REQ,
                                                 sizeof(sctp_init_t) + addr_len);
  sctp_init_t *init = &msg->ittiMsg.sctp_init_multi;
  init->port = XNAP_PORT_NUMBER;
  init->ppid = XNAP_SCTP_PPID;
  char *addr_buf = (char *)(init + 1);
  init->bind_address = addr_buf;
  memcpy(addr_buf, local_ip, addr_len);

  LOG_I(XNAP, "[gNB %ld] Binding SCTP listener on %s port %u\n",
        instance, local_ip, XNAP_PORT_NUMBER);

  itti_send_msg_to_task(TASK_SCTP, instance, msg);
}

/* Phase 2: socket bound — connect to each configured peer */
static void xnap_gNB_handle_sctp_init_msg_multi_cnf(instance_t instance,
                                                     sctp_init_msg_multi_cnf_t *cnf)
{
  xnap_gnb_inst_t *inst = getCxtXn(instance);
  AssertFatal(inst != NULL, "Xn instance %ld not found\n", instance);

  inst->multi_sd = cnf->multi_sd;
  if (inst->multi_sd < 0) {
    LOG_E(XNAP, "[gNB %ld] SCTP_INIT_MSG_MULTI_CNF failed — check Xn IP/port config\n", instance);
    return;
  }

  LOG_I(XNAP, "[gNB %ld] SCTP listener ready (multi_sd %d), connecting to %u peer(s)\n",
        instance, inst->multi_sd, inst->nb_peers);

  xnap_peer_t *peer;
  RB_FOREACH(peer, xnap_peer_map, &inst->peers) {
    const char *remote_ip = inst->net_config.candidate_gnb_xn_ip_address[peer->cnx_id];

    MessageDef *msg = itti_alloc_new_message(TASK_XNAP, instance, SCTP_NEW_ASSOCIATION_REQ);
    sctp_new_association_req_t *req = &msg->ittiMsg.sctp_new_association_req;

    req->ulp_cnx_id  = peer->cnx_id;
    req->port        = XNAP_PORT_NUMBER;
    req->ppid        = XNAP_SCTP_PPID;
    req->in_streams  = inst->net_config.sctp_streams.sctp_in_streams;
    req->out_streams = inst->net_config.sctp_streams.sctp_out_streams;

    req->local_address.ipv4 = 1;
    strncpy(req->local_address.ipv4_address,
            inst->net_config.gnb_xn_interface_ip_address,
            sizeof(req->local_address.ipv4_address) - 1);

    req->remote_address.ipv4 = 1;
    strncpy(req->remote_address.ipv4_address,
            remote_ip,
            sizeof(req->remote_address.ipv4_address) - 1);

    LOG_I(XNAP, "[gNB %ld] Initiating SCTP connection to peer %u at %s port %u\n",
          instance, peer->cnx_id, remote_ip, XNAP_PORT_NUMBER);

    itti_send_msg_to_task(TASK_SCTP, instance, msg);
  }
}

static void xnap_gNB_handle_sctp_association_resp(instance_t instance,
                                                   sctp_new_association_resp_t *resp)
{
  xnap_gnb_inst_t *inst = getCxtXn(instance);
  AssertFatal(inst != NULL, "Xn instance %ld not found\n", instance);

  /* Case 1: peer already keyed by assoc_id (established or simultaneous-connect).
   * A SHUTDOWN here means the remote gNB stopped after Xn was up. */
  xnap_peer_t *peer = getXnPeerByAssoc(inst, resp->assoc_id);
  if (peer != NULL) {
    if (resp->sctp_state == SCTP_STATE_SHUTDOWN) {
      LOG_W(XNAP, "[gNB %ld] SCTP_NEW_ASSOCIATION_RESP: peer assoc_id %d shut down\n",
            instance, resp->assoc_id);
      xnap_handle_xn_setup_message(instance, inst, peer, 1 /* shutdown */);
      return;
    }
    /* Simultaneous-connect: remote peer opened to us first via IND, which
     * already inserted it keyed by assoc_id.  Update streams and return —
     * they are the initiator and will send XnSetupRequest to us. */
    LOG_I(XNAP, "[gNB %ld] SCTP_NEW_ASSOCIATION_RESP: peer assoc_id %d already registered "
          "via IND (simultaneous connect), updating streams\n", instance, resp->assoc_id);
    peer->in_streams  = resp->in_streams;
    peer->out_streams = resp->out_streams;
    return;
  }

  /* Case 2: peer still keyed by cnx_id — outgoing connect attempt result. */
  peer = getXnPeerByCnxId(inst, resp->ulp_cnx_id);
  if (peer == NULL) {
    LOG_E(XNAP, "[gNB %ld] SCTP_NEW_ASSOCIATION_RESP: no peer for assoc_id %d cnx_id %u\n",
          instance, resp->assoc_id, resp->ulp_cnx_id);
    return;
  }

  if (resp->sctp_state != SCTP_STATE_ESTABLISHED) {
    LOG_W(XNAP, "[gNB %ld] SCTP association failed for peer cnx_id %u (state %u)\n",
          instance, resp->ulp_cnx_id, resp->sctp_state);
    return;
  }

  /* Transition peer from cnx_id-keyed to assoc_id-keyed in the RB tree */
  xnap_peer_set_assoc_id(inst, peer, resp->assoc_id);
  peer->in_streams  = resp->in_streams;
  peer->out_streams = resp->out_streams;

  LOG_I(XNAP, "[gNB %ld] SCTP association established with peer cnx_id %u assoc_id %d "
        "(in %u out %u) — sending XnSetupRequest\n",
        instance, resp->ulp_cnx_id, resp->assoc_id, resp->in_streams, resp->out_streams);

  xnap_gNB_generate_xn_setup_request(instance, inst, peer);
}

static void xnap_gNB_handle_sctp_association_ind(instance_t instance,
                                                  sctp_new_association_ind_t *ind)
{
  xnap_gnb_inst_t *inst = getCxtXn(instance);
  AssertFatal(inst != NULL, "Xn instance %ld not found\n", instance);

  /* Guard against duplicate IND for the same assoc_id */
  if (getXnPeerByAssoc(inst, ind->assoc_id) != NULL) {
    LOG_W(XNAP, "[gNB %ld] SCTP_NEW_ASSOCIATION_IND: assoc_id %d already registered\n",
          instance, ind->assoc_id);
    return;
  }

  /* Incoming connection — remote peer is the initiator.
   * Assign a cnx_id from the global counter (used only for bookkeeping;
   * tree is keyed by assoc_id because assoc_id != -1 from the start). */
  xnap_peer_t *peer = calloc(1, sizeof(*peer));
  AssertFatal(peer != NULL, "calloc failed for incoming Xn peer\n");

  peer->cnx_id    = xnap_fetch_add_cnx_id();
  peer->assoc_id  = ind->assoc_id;
  peer->in_streams  = ind->in_streams;
  peer->out_streams = ind->out_streams;

  RB_INSERT(xnap_peer_map, &inst->peers, peer);
  inst->nb_peers++;

  LOG_I(XNAP, "[gNB %ld] Incoming Xn connection: assoc_id %d cnx_id %u "
        "(in %u out %u) — waiting for XnSetupRequest\n",
        instance, ind->assoc_id, peer->cnx_id, ind->in_streams, ind->out_streams);
}

void *xnap_task(void *args)
{
  UNUSED(args);
  LOG_I(XNAP, "Starting XnAP task\n");
  itti_mark_task_ready(TASK_XNAP);

  while (1) {
    MessageDef *msg = NULL;
    itti_receive_msg(TASK_XNAP, &msg);
    const instance_t instance = ITTI_MSG_DESTINATION_INSTANCE(msg);
    const int msgType = ITTI_MSG_ID(msg);
    LOG_D(XNAP, "XnAP received %s for instance %ld\n", ITTI_MSG_NAME(msg), instance);

    switch (msgType) {
      case XNAP_REGISTER_GNB_REQ:
        xnap_gNB_handle_register_gnb(instance, &XNAP_REGISTER_GNB_REQ(msg));
        break;

      case SCTP_INIT_MSG_MULTI_CNF:
        xnap_gNB_handle_sctp_init_msg_multi_cnf(instance, &SCTP_INIT_MSG_MULTI_CNF(msg));
        break;

      case SCTP_NEW_ASSOCIATION_RESP:
        xnap_gNB_handle_sctp_association_resp(instance, &SCTP_NEW_ASSOCIATION_RESP(msg));
        break;

      case SCTP_NEW_ASSOCIATION_IND:
        xnap_gNB_handle_sctp_association_ind(instance, &SCTP_NEW_ASSOCIATION_IND(msg));
        break;

      default:
        LOG_E(XNAP, "Unknown message type %d (%s)\n", msgType, ITTI_MSG_NAME(msg));
        break;
    }

    int result = itti_free(ITTI_MSG_ORIGIN_ID(msg), msg);
    AssertFatal(result == EXIT_SUCCESS, "Failed to free ITTI message (%d)\n", result);
    msg = NULL;
  }
}
