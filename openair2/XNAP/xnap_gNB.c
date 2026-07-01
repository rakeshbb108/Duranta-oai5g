/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xnap_gNB.h"
#include "common/utils/LOG/log.h"
#include "common/platform_types.h"
#include "common/utils/ocp_itti/intertask_interface.h"

void *xnap_task(void *args){
  UNUSED(args);
  LOG_I(XNAP, "Starting XnAP at CUCP\n");
  itti_mark_task_ready(TASK_XNAP);
  int result;
  while (1) {
    MessageDef *msg = NULL;
    itti_receive_msg(TASK_XNAP, &msg);
    const instance_t myInstance = ITTI_MSG_DESTINATION_INSTANCE(msg);
    sctp_assoc_t assoc_id = ITTI_MSG_ORIGIN_INSTANCE(msg);
    const int msgType = ITTI_MSG_ID(msg);
    LOG_D(XNAP, "XnAP recieved task %s for instance %ld: sending message via assoc_id %d\n",
         ITTI_MSG_NAME(msg), myInstance, assoc_id);
    switch (msgType) {
      case XNAP_REGISTER_GNB_REQ: {

      }
 
      default:
        LOG_E(XNAP, "Unknown message received in TASK_CUUP_E1\n");
        break;
    }
    result = itti_free(ITTI_MSG_ORIGIN_ID(msg), msg);
    AssertFatal(result == EXIT_SUCCESS, "Failed to free memory (%d) in xnap_task!\n", result);
    msg = NULL;
  }
}
