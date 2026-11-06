/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* reads the dl_flow_control section; linked into nr-softmodem and nr-cuup */

#include "nr_pdcp_dl_flow_ctrl.h"
#include "common/config/config_userapi.h"
#include "common/utils/LOG/log.h"
#include "openair2/GNB_APP/gnb_paramdef.h"

void nr_pdcp_dl_flow_ctrl_read_config(ngran_node_t node_type)
{
  GET_PARAMS(p, DL_FLOW_CONTROL_PARAMS_DESC, CONFIG_STRING_DL_FLOW_CONTROL);
  const bool hosts_pdcp = node_type == ngran_gNB || node_type == ngran_gNB_CU || node_type == ngran_gNB_CUUP;
  const bool hosts_rlc = node_type == ngran_gNB || node_type == ngran_gNB_DU;
  /* a parameter in a process that does not use it would silently do nothing */
  AssertFatal(hosts_pdcp || !config_isparamset(p, CONFIG_DL_FLOW_CONTROL_ENABLE_IDX),
              "%s.enable is for the process hosting PDCP (CU-UP, CU or monolithic gNB), not this one\n",
              CONFIG_STRING_DL_FLOW_CONTROL);
  AssertFatal(hosts_pdcp || !config_isparamset(p, CONFIG_DL_FLOW_CONTROL_STALL_TIMEOUT_MS_IDX),
              "%s.stall_timeout_ms is for the process hosting PDCP (CU-UP, CU or monolithic gNB), not this one\n",
              CONFIG_STRING_DL_FLOW_CONTROL);
  AssertFatal(hosts_rlc || !config_isparamset(p, CONFIG_DL_FLOW_CONTROL_TARGET_QUEUE_BYTES_IDX),
              "%s.target_queue_bytes is for the process hosting RLC (DU or monolithic gNB), not this one\n",
              CONFIG_STRING_DL_FLOW_CONTROL);

  nr_dl_flow_ctrl_config_t c = {
      .enable = hosts_pdcp && *p[CONFIG_DL_FLOW_CONTROL_ENABLE_IDX].iptr != 0,
      .target_queue_bytes = hosts_rlc ? *p[CONFIG_DL_FLOW_CONTROL_TARGET_QUEUE_BYTES_IDX].uptr : 0,
      .stall_timeout_ms = *p[CONFIG_DL_FLOW_CONTROL_STALL_TIMEOUT_MS_IDX].iptr,
  };
  AssertFatal(c.stall_timeout_ms >= 0, "%s.stall_timeout_ms must be >= 0\n", CONFIG_STRING_DL_FLOW_CONTROL);
  AssertFatal(node_type != ngran_gNB || !c.enable || c.target_queue_bytes > 0,
              "%s: a monolithic gNB with enable = 1 needs target_queue_bytes > 0\n",
              CONFIG_STRING_DL_FLOW_CONTROL);
  nr_pdcp_dl_flow_ctrl_configure(&c);
  if (c.enable || c.target_queue_bytes > 0)
    LOG_I(PDCP,
          "DL flow control: enable %d, target_queue_bytes %u, stall_timeout_ms %d\n",
          c.enable,
          c.target_queue_bytes,
          c.stall_timeout_ms);
}
