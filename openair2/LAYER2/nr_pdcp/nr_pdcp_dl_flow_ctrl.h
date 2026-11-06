/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef NR_PDCP_DL_FLOW_CTRL_H_
#define NR_PDCP_DL_FLOW_CTRL_H_

/* gNB DL flow control at the node hosting PDCP: DL PDCP Data PDUs of an RLC AM DRB are
 * held while the lower layer has no room, so that the DL queue stays in the PDCP host
 * instead of growing in RLC. On F1-U the room is the desired buffer size of the DL DATA
 * DELIVERY STATUS (TS 38.425); in a monolithic gNB it is target_queue_bytes minus the
 * RLC DL queue. Held PDUs already have their COUNT (TS 38.323 5.2.1) and are in the Xn HO
 * shadow ring, so a handover forwards them; they obey discardTimer (TS 38.323 5.3). */

#include <stdbool.h>
#include <stdint.h>
#include "common/platform_types.h"

/* config section dl_flow_control */
typedef struct {
  bool enable;                 /* PDCP host: hold DL PDCP PDUs while the lower layer has no room */
  uint32_t target_queue_bytes; /* RLC host: DL RLC queue to keep (DU, monolithic) */
  int stall_timeout_ms;        /* PDCP host on F1-U: release one held PDU if no DDDS for this long */
} nr_dl_flow_ctrl_config_t;

void nr_pdcp_dl_flow_ctrl_configure(const nr_dl_flow_ctrl_config_t *config);
const nr_dl_flow_ctrl_config_t *nr_pdcp_dl_flow_ctrl_config(void);

typedef struct nr_pdcp_fc_pdu_s {
  struct nr_pdcp_fc_pdu_s *next;
  int size;
  int sdu_id; /* the PDU's PDCP COUNT, passed on to the lower layer */
  uint64_t t_held;
  char data[];
} nr_pdcp_fc_pdu_t;

typedef struct nr_pdcp_dl_fc_s {
  nr_pdcp_fc_pdu_t *head;
  nr_pdcp_fc_pdu_t *tail;
  int count;
  int64_t bytes;
  int64_t credit;         /* octets the lower layer may still take; INT64_MAX before the first report */
  uint64_t last_progress; /* time of the last credit update or stall release */
  uint32_t dropped_expired;
} nr_pdcp_dl_fc_t;

/* send a PDCP Data PDU to the lower layer (F1-U or RLC) */
typedef void (*nr_pdcp_fc_send_t)(ue_id_t ue_id, int rb_id, char *buf, int size, int sdu_id);

nr_pdcp_dl_fc_t *nr_pdcp_dl_fc_new(uint64_t now);
void nr_pdcp_dl_fc_free(nr_pdcp_dl_fc_t *fc);
/* drop all held PDUs, e.g. at the Xn HO DL freeze: the shadow ring forwards them */
int nr_pdcp_dl_fc_clear(nr_pdcp_dl_fc_t *fc);
/* a new PDU: sent at once if nothing is held and it fits the credit, else held */
void nr_pdcp_dl_fc_submit(nr_pdcp_dl_fc_t *fc, uint64_t now, ue_id_t ue_id, int rb_id, char *buf, int size, int sdu_id, nr_pdcp_fc_send_t send);
/* the lower layer can take credit octets more: send held PDUs, in order, that fit */
void nr_pdcp_dl_fc_set_credit(nr_pdcp_dl_fc_t *fc, uint64_t now, int64_t credit, ue_id_t ue_id, int rb_id, nr_pdcp_fc_send_t send);
/* 1 ms tick: drop PDUs held past discard_timer (ms, < 0 infinity); with stall_timeout_ms > 0,
 * release one PDU if no progress for that long (a DU reports only when delivery advances) */
void nr_pdcp_dl_fc_tick(nr_pdcp_dl_fc_t *fc,
                        uint64_t now,
                        int discard_timer,
                        int stall_timeout_ms,
                        ue_id_t ue_id,
                        int rb_id,
                        nr_pdcp_fc_send_t send);

#endif /* NR_PDCP_DL_FLOW_CTRL_H_ */
