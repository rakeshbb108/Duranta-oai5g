/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef XNAP_GNB_H_
#define XNAP_GNB_H_

#include <stdint.h>
#include "common/platform_types.h"
#include "openair2/COMMON/sctp_messages_types.h"

int is_xnap_enabled(void);
void *xnap_task(void *arg);

void xnap_gNB_itti_send_sctp_data(instance_t instance,
                                   sctp_assoc_t assoc_id,
                                   uint8_t *buffer,
                                   uint32_t length,
                                   uint16_t stream);

#endif /* XNAP_GNB_H_ */
