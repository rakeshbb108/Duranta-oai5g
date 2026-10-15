/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* Xn HO source DL forwarding: SDUs not confirmed delivered are forwarded with their
 * PDCP SN in ascending COUNT order once DL is frozen, and the DL COUNT reported
 * afterwards is the first COUNT without SN (TX_NEXT at freeze). */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "nr_pdcp/nr_pdcp_entity.h"
#include "common/utils/assertions.h"
#include "common/utils/LOG/log.h"

#define CHECK(c)                                                             \
  do {                                                                       \
    if (!(c)) {                                                              \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #c); \
      exit(1);                                                               \
    }                                                                        \
  } while (0)

#define MAX_FWD 16
static int fwd_n;
static int fwd_sn[MAX_FWD];
static char fwd_payload[MAX_FWD];

static void forward_sdu(void *data, ue_id_t ue_id, int rb_id, const char *buf, int size, int sn, int sn_size)
{
  CHECK(fwd_n < MAX_FWD);
  CHECK(size == 1);
  fwd_sn[fwd_n] = sn;
  fwd_payload[fwd_n] = buf[0];
  fwd_n++;
}

static void deliver_sdu(void *data, nr_pdcp_entity_t *entity, char *buf, int size, const nr_pdcp_integrity_data_t *msg_integrity)
{
}

#define MAX_TX 16
static int tx_n;
static uint32_t tx_count[MAX_TX];
static int tx_sn[MAX_TX];
static char tx_payload[MAX_TX];

/* no security: the PDU is header + plaintext SDU */
static void deliver_pdu(void *data, ue_id_t ue_id, int rb_id, char *buf, int size, int sdu_id)
{
  CHECK(tx_n < MAX_TX);
  CHECK(data == NULL); /* deliver_pdu_drb_gnb() asserts it */
  const uint8_t *p = (const uint8_t *)buf;
  bool is_12 = size == 3;
  tx_count[tx_n] = (uint32_t)sdu_id;
  tx_sn[tx_n] = is_12 ? ((p[0] & 0x0f) << 8) | p[1] : ((p[0] & 0x03) << 16) | (p[1] << 8) | p[2];
  tx_payload[tx_n] = buf[size - 1];
  tx_n++;
}

static nr_pdcp_entity_t *new_drb(int sn_size)
{
  nr_pdcp_entity_security_keys_and_algos_t sec = {0};
  return new_nr_pdcp_entity(NR_PDCP_DRB_AM, 1, 1, 1, false, false, deliver_sdu, NULL, deliver_pdu, NULL, sn_size, 100, -1, &sec);
}

/* send one 1-byte SDU whose payload is its index; returns the COUNT it got */
static uint32_t send_sdu(nr_pdcp_entity_t *e, char payload)
{
  char pdu[16];
  uint32_t count = e->tx_next;
  CHECK(e->process_sdu(e, &payload, 1, 0, pdu, sizeof(pdu)) > 0);
  return count;
}

static void test_forward_unacked_in_order(void)
{
  nr_pdcp_entity_t *e = new_drb(18);
  for (char i = 0; i < 5; i++)
    send_sdu(e, i);
  /* RLC AM confirms COUNT 3 before 1: COUNT 0..2 stay pending, only 1 and 3 go */
  nr_pdcp_shadow_ring_ack(e->shadow_ring, 3);
  nr_pdcp_shadow_ring_ack(e->shadow_ring, 1);

  fwd_n = 0;
  nr_pdcp_entity_start_dl_forwarding(e, 1, forward_sdu, NULL);
  CHECK(fwd_n == 3);
  CHECK(fwd_sn[0] == 0 && fwd_payload[0] == 0);
  CHECK(fwd_sn[1] == 2 && fwd_payload[1] == 2);
  CHECK(fwd_sn[2] == 4 && fwd_payload[2] == 4);
  CHECK(e->shadow_ring->count == 0);

  /* SN status read after the freeze: the target continues at TX_NEXT */
  nr_pdcp_count_t dl = e->get_pdcp_count_dl(e);
  CHECK(dl.hfn == 0 && dl.sn == 5);
  CHECK(e->forward_sdu == forward_sdu);
  e->delete_entity(e);
}

static void test_forward_sn_wraps(void)
{
  nr_pdcp_entity_t *e = new_drb(12);
  e->set_pdcp_count_dl(e, (nr_pdcp_count_t){.hfn = 2, .sn = 4094}, 12);
  for (char i = 0; i < 4; i++)
    send_sdu(e, i);
  fwd_n = 0;
  nr_pdcp_entity_start_dl_forwarding(e, 1, forward_sdu, NULL);
  CHECK(fwd_n == 4);
  CHECK(fwd_sn[0] == 4094 && fwd_sn[1] == 4095 && fwd_sn[2] == 0 && fwd_sn[3] == 1);
  nr_pdcp_count_t dl = e->get_pdcp_count_dl(e);
  CHECK(dl.hfn == 3 && dl.sn == 2);
  e->delete_entity(e);
}

static void test_ack_unknown_count(void)
{
  nr_pdcp_entity_t *e = new_drb(18);
  send_sdu(e, 0);
  send_sdu(e, 1);
  nr_pdcp_shadow_ring_ack(e->shadow_ring, 7);
  CHECK(e->shadow_ring->count == 2);
  nr_pdcp_shadow_ring_ack(e->shadow_ring, 1);
  CHECK(e->shadow_ring->count == 1 && e->shadow_ring->tail == e->shadow_ring->head);
  send_sdu(e, 2);
  CHECK(e->shadow_ring->count == 2 && e->shadow_ring->tail->count == 2);
  e->delete_entity(e);
}

/* target: forwarded SDUs wait for the SN status, then keep their arrival order; an SDU
 * with SN gets the COUNT below the received DL COUNT with that SN (here across an HFN
 * boundary), an SDU without SN is numbered from the DL COUNT */
static void test_target_hold_and_count(void)
{
  nr_pdcp_entity_t *e = new_drb(12);
  e->fwd_hold = true;
  char p[4] = {'a', 'b', 'c', 'd'};
  tx_n = 0;
  nr_pdcp_entity_recv_forwarded_sdu(e, 1, &p[0], 1, 4094);
  nr_pdcp_entity_recv_forwarded_sdu(e, 1, &p[1], 1, 4095);
  nr_pdcp_entity_recv_forwarded_sdu(e, 1, &p[2], 1, 0);
  nr_pdcp_entity_recv_forwarded_sdu(e, 1, &p[3], 1, -1);
  CHECK(tx_n == 0);

  e->set_pdcp_count_dl(e, (nr_pdcp_count_t){.hfn = 3, .sn = 1}, 12);
  nr_pdcp_entity_release_forwarded(e, 1);
  CHECK(tx_n == 4);
  CHECK(tx_count[0] == 3 * 4096 - 2 && tx_sn[0] == 4094 && tx_payload[0] == 'a');
  CHECK(tx_count[1] == 3 * 4096 - 1 && tx_sn[1] == 4095 && tx_payload[1] == 'b');
  CHECK(tx_count[2] == 3 * 4096 && tx_sn[2] == 0 && tx_payload[2] == 'c');
  CHECK(tx_count[3] == 3 * 4096 + 1 && tx_sn[3] == 1 && tx_payload[3] == 'd');
  CHECK(e->tx_next == 3 * 4096 + 2 && !e->fwd_hold);

  /* after release: sent as they arrive */
  nr_pdcp_entity_recv_forwarded_sdu(e, 1, &p[0], 1, -1);
  CHECK(tx_n == 5 && tx_count[4] == 3 * 4096 + 2);
  e->delete_entity(e);
}

static void test_target_count_window(void)
{
  nr_pdcp_entity_t *e = new_drb(12);
  e->set_pdcp_count_dl(e, (nr_pdcp_count_t){.hfn = 3, .sn = 1}, 12);
  uint32_t count;
  /* the SN of DL COUNT itself was not numbered by the source */
  CHECK(!nr_pdcp_entity_forwarded_count(e, 1, &count));
  /* more than a window (2048) below DL COUNT */
  CHECK(!nr_pdcp_entity_forwarded_count(e, 2000, &count));
  CHECK(nr_pdcp_entity_forwarded_count(e, 2050, &count) && count == 3 * 4096 + 1 - 2047);
  CHECK(!nr_pdcp_entity_forwarded_count(e, 4096, &count));
  tx_n = 0;
  char c = 'x';
  nr_pdcp_entity_recv_forwarded_sdu(e, 1, &c, 1, 1);
  CHECK(tx_n == 0);
  e->delete_entity(e);

  /* 18-bit SN, no HFN: nothing below COUNT 0 */
  e = new_drb(18);
  e->set_pdcp_count_dl(e, (nr_pdcp_count_t){.hfn = 0, .sn = 5}, 18);
  CHECK(nr_pdcp_entity_forwarded_count(e, 0, &count) && count == 0);
  CHECK(!nr_pdcp_entity_forwarded_count(e, 262143, &count));
  e->delete_entity(e);
}

int main(void)
{
  logInit();
  test_forward_unacked_in_order();
  test_forward_sn_wraps();
  test_ack_unknown_count();
  test_target_hold_and_count();
  test_target_count_window();
  printf("pdcp_forwarding_tests: OK\n");
  return 0;
}
