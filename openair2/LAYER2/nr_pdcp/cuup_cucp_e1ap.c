/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "cuup_cucp_if.h"
#include "intertask_interface.h"
#include "e1ap_messages_types.h"
#include "e1ap_bearer_context_management.h"
#include "openair2/E1AP/e1ap.h"

static void bearer_setup_response_e1ap(const e1ap_bearer_setup_resp_t *resp)
{
  MessageDef *msg_p = itti_alloc_new_message(TASK_CUUP_E1, 0, E1AP_BEARER_CONTEXT_SETUP_RESP);
  e1ap_bearer_setup_resp_t *bearer_resp = &E1AP_BEARER_CONTEXT_SETUP_RESP(msg_p);
  *bearer_resp = cp_bearer_context_setup_response(resp);
  itti_send_msg_to_task (TASK_CUUP_E1, 0, msg_p);
}

static void bearer_modif_response_e1ap(const e1ap_bearer_modif_resp_t *resp)
{
  /* Called on TASK_CUUP_E1 itself: queueing to that task would hold the response until the
   * handler returns, i.e. after the Xn HO backlog is forwarded, so send it right away */
  const e1ap_upcp_inst_t *inst = getCxtE1(0);
  AssertFatal(inst, "no E1 instance found\n");
  e1apCUUP_send_BEARER_CONTEXT_MODIFICATION_RESPONSE(inst->cuup.assoc_id, resp);
}

static void bearer_mod_required_e1ap(const e1ap_bearer_mod_required_t *req)
{
  MessageDef *msg_p = itti_alloc_new_message(TASK_CUUP_E1, 0, E1AP_BEARER_CONTEXT_MODIFICATION_REQUIRED);
  e1ap_bearer_mod_required_t *msg_req = &E1AP_BEARER_CONTEXT_MODIFICATION_REQUIRED(msg_p);
  *msg_req = cp_bearer_context_mod_required(req);
  itti_send_msg_to_task(TASK_CUUP_E1, 0, msg_p);
}

static void bearer_release_complete_e1ap(const e1ap_bearer_release_cplt_t *cplt)
{
  MessageDef *msg_p = itti_alloc_new_message(TASK_CUUP_E1, 0, E1AP_BEARER_CONTEXT_RELEASE_CPLT);
  e1ap_bearer_release_cplt_t *msg_cplt = &E1AP_BEARER_CONTEXT_RELEASE_CPLT(msg_p);
  *msg_cplt = *cplt;
  itti_send_msg_to_task (TASK_CUUP_E1, 0, msg_p);
}

void cuup_cucp_init_e1ap(e1_if_t *iface)
{
  iface->bearer_setup_response = bearer_setup_response_e1ap;
  iface->bearer_modif_response = bearer_modif_response_e1ap;
  iface->bearer_mod_required = bearer_mod_required_e1ap;
  iface->bearer_release_complete = bearer_release_complete_e1ap;
}
