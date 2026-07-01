/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef XNAP_INTERFACE_H_
#define XNAP_INTERFACE_H_

#include "openair2/COMMON/ngap_messages_types.h"
#include "openair2/COMMON/xnap_messages_types.h"

xnap_setup_info_t Read_Xn_Setup_Info(const ngap_register_gnb_cnf_t *cnf, uint32_t gnb_idx);
xnap_net_config_t Read_IPconfig_Xn(uint32_t gnb_idx);

#endif /* XNAP_INTERFACE_H_ */
