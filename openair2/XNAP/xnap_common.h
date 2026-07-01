/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#ifndef XNAP_COMMON_H_
#define XNAP_COMMON_H_

#include "tree.h"
#include "common/platform_types.h"
#include "openair2/COMMON/sctp_messages_types.h"
#include "openair2/COMMON/xnap_messages_types.h"

/* State of one peer gNB Xn connection.
 *
 * Dual-key ordering (mirrors the NGAP AMF pattern):
 *   - Before SCTP connects: assoc_id == -1, tree is ordered by cnx_id.
 *   - After SCTP connects : call xnap_peer_set_assoc_id() which removes the
 *     node, sets the real assoc_id, and re-inserts so the tree is then
 *     ordered by assoc_id.  All subsequent lookups use assoc_id.
 */
typedef struct xnap_peer_s {
  RB_ENTRY(xnap_peer_s) entry;
  uint16_t          cnx_id;            /* unique per-candidate index, set at init */
  sctp_assoc_t      assoc_id;          /* -1 until SCTP association is up */
  uint32_t          remote_gnb_id;     /* filled after Xn Setup Response */
  xnap_setup_info_t remote_setup_info; /* filled after Xn Setup Response */
} xnap_peer_t;

/* Per-local-gNB Xn state, indexed by instance number. */
typedef struct xnap_gnb_inst_s {
  instance_t        instance;
  uint32_t          gnb_id;
  xnap_setup_info_t setup_info;  /* local gNB's own identity/capabilities */
  xnap_net_config_t net_config;
  uint8_t           nb_peers;    /* number of candidates inserted into tree */
  RB_HEAD(xnap_peer_map, xnap_peer_s) peers;
} xnap_gnb_inst_t;

/* RB_HEAD inside xnap_gnb_inst_t above defines struct xnap_peer_map,
 * so RB_PROTOTYPE must come after that definition — same pattern as NGAP. */
int xnap_peer_compare(struct xnap_peer_s *p1, struct xnap_peer_s *p2);
RB_PROTOTYPE(xnap_peer_map, xnap_peer_s, entry, xnap_peer_compare);

xnap_gnb_inst_t *getCxtXn(instance_t instance);

/* Lookup by real assoc_id (used after SCTP connects). */
xnap_peer_t *getXnPeerByAssoc(xnap_gnb_inst_t *inst, sctp_assoc_t assoc_id);

/* Lookup by cnx_id (used before SCTP connects, e.g. on SCTP_NEW_ASSOCIATION). */
xnap_peer_t *getXnPeerByCnxId(xnap_gnb_inst_t *inst, uint16_t cnx_id);

/* Transition a peer from cnx_id-keyed to assoc_id-keyed:
 * removes from tree, sets assoc_id, re-inserts. */
void xnap_peer_set_assoc_id(xnap_gnb_inst_t *inst, xnap_peer_t *peer, sctp_assoc_t assoc_id);

void createXninst(instance_t instance, xnap_setup_info_t *setup_info, xnap_net_config_t *net_config);

#endif /* XNAP_COMMON_H_ */
