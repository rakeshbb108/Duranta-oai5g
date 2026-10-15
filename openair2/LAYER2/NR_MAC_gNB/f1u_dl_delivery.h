/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef F1U_DL_DELIVERY_H_
#define F1U_DL_DELIVERY_H_

#include <stdint.h>

/* DU: highest NR PDCP SN successfully delivered in sequence to the UE, per DRB, for the
 * DL DATA DELIVERY STATUS (TS 38.425). The CU-UP requests it with Report Delivered on DL
 * USER DATA; the SNs are tracked in submission order, so that a PDU confirmed by RLC AM
 * before an earlier one does not count until the earlier one is confirmed too. */

/* report once this many PDUs were delivered in sequence since the last report, or when
 * no tracked PDU of the DRB is pending anymore */
#define F1U_DL_DELIVERY_REPORT_EVERY 32

typedef void (*f1u_dl_delivery_report_t)(uint32_t ue_id, int drb_id, uint32_t highest_delivered_sn, uint32_t desired_buffer_size);

void f1u_dl_delivery_set_report_cb(f1u_dl_delivery_report_t cb);
/* a PDU with Report Delivered for this PDCP SN is given to RLC */
void f1u_dl_delivery_submitted(uint32_t ue_id, int drb_id, uint32_t sn);
/* RLC confirmed the delivery of the PDU with this PDCP SN; may report */
void f1u_dl_delivery_delivered(uint32_t ue_id, int drb_id, uint32_t sn, uint32_t desired_buffer_size);
void f1u_dl_delivery_remove_ue(uint32_t ue_id);

#endif /* F1U_DL_DELIVERY_H_ */
