/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* gNB DL flow control at the PDCP host (nr_pdcp_dl_flow_ctrl.h) */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "openair2/LAYER2/nr_pdcp/nr_pdcp_dl_flow_ctrl.h"
#include "openair2/LAYER2/nr_pdcp/nr_pdcp_entity.h"
#include "common/utils/LOG/log.h"

#define CHECK(c)                                                             \
  do {                                                                       \
    if (!(c)) {                                                              \
      printf("%s:%d:%s: CHECK failed: %s\n", __FILE__, __LINE__, __func__, #c); \
      exit(1);                                                               \
    }                                                                        \
  } while (0)

#define MAX_SENT 16
static int sent_n;
static int sent_id[MAX_SENT];
static int sent_size[MAX_SENT];

static void send_pdu(ue_id_t ue_id, int rb_id, char *buf, int size, int sdu_id)
{
  CHECK(ue_id == 7 && rb_id == 1 && buf != NULL);
  if (sent_n < MAX_SENT) {
    sent_id[sent_n] = sdu_id;
    sent_size[sent_n] = size;
  }
  sent_n++;
}

static char buf[1000];

static void submit(nr_pdcp_dl_fc_t *fc, uint64_t now, int size, int sdu_id)
{
  nr_pdcp_dl_fc_submit(fc, now, 7, 1, buf, size, sdu_id, send_pdu);
}

/* before the first DDDS nothing is held; a report then limits, and held PDUs go in order */
static void test_credit(void)
{
  sent_n = 0;
  nr_pdcp_dl_fc_t *fc = nr_pdcp_dl_fc_new(0);
  submit(fc, 0, 500, 0);
  CHECK(sent_n == 1 && fc->count == 0);

  nr_pdcp_dl_fc_set_credit(fc, 1, 700, 7, 1, send_pdu);
  submit(fc, 1, 500, 1);
  submit(fc, 1, 500, 2); /* 200 left: held */
  submit(fc, 1, 100, 3); /* fits, but held behind 2 to keep the order */
  CHECK(sent_n == 2 && fc->count == 2 && fc->bytes == 600);

  nr_pdcp_dl_fc_set_credit(fc, 2, 550, 7, 1, send_pdu);
  CHECK(sent_n == 3 && sent_id[2] == 2 && fc->count == 1); /* 50 left, 100 waits */
  nr_pdcp_dl_fc_set_credit(fc, 3, 0, 7, 1, send_pdu);
  CHECK(sent_n == 3);
  nr_pdcp_dl_fc_set_credit(fc, 4, 1000, 7, 1, send_pdu);
  CHECK(sent_n == 4 && sent_id[3] == 3 && fc->count == 0 && fc->credit == 900);
  nr_pdcp_dl_fc_free(fc);
}

/* no report while PDUs are held: one PDU per stall timeout, none without a timeout */
static void test_stall(void)
{
  sent_n = 0;
  nr_pdcp_dl_fc_t *fc = nr_pdcp_dl_fc_new(0);
  nr_pdcp_dl_fc_set_credit(fc, 0, 0, 7, 1, send_pdu);
  submit(fc, 0, 100, 10);
  submit(fc, 0, 100, 11);
  nr_pdcp_dl_fc_tick(fc, 19, -1, 20, 7, 1, send_pdu);
  CHECK(sent_n == 0);
  nr_pdcp_dl_fc_tick(fc, 20, -1, 20, 7, 1, send_pdu);
  CHECK(sent_n == 1 && sent_id[0] == 10);
  nr_pdcp_dl_fc_tick(fc, 39, -1, 20, 7, 1, send_pdu);
  CHECK(sent_n == 1);
  nr_pdcp_dl_fc_tick(fc, 1000, -1, 0, 7, 1, send_pdu);
  CHECK(sent_n == 1 && fc->count == 1);
  nr_pdcp_dl_fc_free(fc);
}

/* discardTimer (TS 38.323 5.3) drops held PDUs; the DL freeze drops the rest */
static void test_discard_and_clear(void)
{
  sent_n = 0;
  nr_pdcp_dl_fc_t *fc = nr_pdcp_dl_fc_new(0);
  nr_pdcp_dl_fc_set_credit(fc, 0, 0, 7, 1, send_pdu);
  submit(fc, 0, 100, 20);
  submit(fc, 50, 100, 21);
  submit(fc, 60, 100, 22);
  nr_pdcp_dl_fc_tick(fc, 99, 100, 0, 7, 1, send_pdu);
  CHECK(fc->count == 3);
  nr_pdcp_dl_fc_tick(fc, 150, 100, 0, 7, 1, send_pdu);
  CHECK(fc->count == 1 && fc->dropped_expired == 2 && fc->head->sdu_id == 22);
  CHECK(nr_pdcp_dl_fc_clear(fc) == 1 && fc->count == 0 && fc->bytes == 0 && fc->head == NULL);
  CHECK(sent_n == 0);
  nr_pdcp_dl_fc_free(fc);
}

static void deliver_sdu(void *data, nr_pdcp_entity_t *e, char *b, int s, const nr_pdcp_integrity_data_t *i) {}
static void deliver_pdu(void *data, ue_id_t ue_id, int rb_id, char *b, int s, int id) {}

static nr_pdcp_entity_t *new_entity(nr_pdcp_entity_type_t type, bool is_gnb)
{
  nr_pdcp_entity_security_keys_and_algos_t sec = {0};
  return new_nr_pdcp_entity(type, is_gnb, 1, 1, false, false, deliver_sdu, NULL, deliver_pdu, NULL, 18, 100, -1, &sec);
}

/* only gNB RLC AM DRBs get flow control, and only when enabled */
static void test_entity_enable(void)
{
  nr_dl_flow_ctrl_config_t c = {0};
  nr_pdcp_dl_flow_ctrl_configure(&c);
  nr_pdcp_entity_t *e = new_entity(NR_PDCP_DRB_AM, true);
  CHECK(e->dl_fc == NULL);
  e->delete_entity(e);

  c.enable = true;
  nr_pdcp_dl_flow_ctrl_configure(&c);
  e = new_entity(NR_PDCP_DRB_AM, true);
  CHECK(e->dl_fc != NULL);
  e->delete_entity(e);
  e = new_entity(NR_PDCP_DRB_AM, false);
  CHECK(e->dl_fc == NULL);
  e->delete_entity(e);
  e = new_entity(NR_PDCP_SRB, true);
  CHECK(e->dl_fc == NULL);
  e->delete_entity(e);
}

int main(void)
{
  logInit();
  test_credit();
  test_stall();
  test_discard_and_clear();
  test_entity_enable();
  printf("pdcp_dl_flow_ctrl_tests: OK\n");
  return 0;
}
