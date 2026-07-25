/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef GTPU_EXTENSIONS_H
#define GTPU_EXTENSIONS_H

#include <stdint.h>
#include <stdbool.h>

#include "nrup_dl_user_data.h"
#include "nrup_dl_data_delivery_status.h"

typedef enum {
  GTPU_EXT_NONE,
  /* 38.415 */
  GTPU_EXT_UL_PDU_SESSION_INFORMATION,
  /* 38.425 */
  GTPU_EXT_DL_DATA_DELIVERY_STATUS,
  GTPU_EXT_DL_USER_DATA,
  /* 29.281 5.2.2.2 / 5.2.2.2A: carry the PDCP SN of a DL SDU forwarded on
   * Xn/N3 during handover, so the target applies it under its original SN.
   * Short (15-bit field) is used for a 12-bit PDCP SN, Long (18-bit field)
   * for an 18-bit PDCP SN. */
  GTPU_EXT_PDCP_PDU_NUMBER,
  GTPU_EXT_LONG_PDCP_PDU_NUMBER,
} gtpu_extension_header_type_t;

/* 38.415 */
typedef struct {
  /* not all fields are present, to be refined if needed */
  bool qmp;
  bool dl_delay_ind;
  bool ul_delay_ind;
  bool snp;
  bool n3n9_delay_ind;
  bool new_ie_flag;
  int qfi;
} ul_pdu_session_information_t;

/* 29.281 5.2.2.2 (short, 15-bit) and 5.2.2.2A (long, 18-bit) */
typedef struct {
  uint32_t pdcp_pdu_number; /* PDCP SN (TS 38.323) */
} pdcp_pdu_number_t;

typedef struct {
  gtpu_extension_header_type_t type;
  union {
    ul_pdu_session_information_t ul_pdu_session_information;
    nrup_dl_data_delivery_status_t dl_data_delivery_status;
    nrup_dl_user_data_t dl_user_data;
    pdcp_pdu_number_t pdcp_pdu_number;
  };
} gtpu_extension_header_t;

int serialize_gtpu_extension_type(gtpu_extension_header_type_t type);
int serialize_extension(gtpu_extension_header_t *ext, gtpu_extension_header_type_t next, uint8_t *out_buf, int out_len);

#endif /* GTPU_EXTENSIONS_H */
