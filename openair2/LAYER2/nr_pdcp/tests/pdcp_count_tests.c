/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* PDCP COUNT accessors used by handover SN status transfer
 * (TS 38.413 9.3.1.108 / TS 38.423 9.2.3.x):
 *   DL COUNT = COUNT to assign to the next DL SDU without an SN (TX_NEXT)
 *   UL COUNT = COUNT of the first missing UL SDU (RX_DELIV) */

#include <stdlib.h>
#include <string.h>

#include "nr_pdcp/nr_pdcp_entity.h"
#include "common/utils/assertions.h"
#include "common/utils/LOG/log.h"

#define CHECK(c)                                                    \
  do {                                                              \
    if (!(c)) {                                                     \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #c); \
      exit(1);                                                      \
    }                                                               \
  } while (0)

static int delivered_count;
static char delivered_buf[64];

static void deliver_sdu(void *data, nr_pdcp_entity_t *entity, char *buf, int size, const nr_pdcp_integrity_data_t *msg_integrity)
{
  delivered_count++;
  memcpy(delivered_buf, buf, size < (int)sizeof(delivered_buf) ? size : (int)sizeof(delivered_buf));
}

static void deliver_pdu(void *data, ue_id_t ue_id, int rb_id, char *buf, int size, int sdu_id)
{
}

static nr_pdcp_entity_t *new_drb(int sn_size)
{
  nr_pdcp_entity_security_keys_and_algos_t sec = {0};
  return new_nr_pdcp_entity(NR_PDCP_DRB_AM, 1, 1, 1, false, false, deliver_sdu, NULL, deliver_pdu, NULL, sn_size, 100, -1, &sec);
}

/* SN of a DL data PDU produced by process_sdu() */
static uint32_t pdu_sn(const uint8_t *pdu, int sn_size)
{
  if (sn_size == 12)
    return ((pdu[0] & 0x0f) << 8) | pdu[1];
  return ((pdu[0] & 0x03) << 16) | (pdu[1] << 8) | pdu[2];
}

static void test_dl_count(int sn_size)
{
  nr_pdcp_entity_t *e = new_drb(sn_size);
  char sdu[8] = "payload";
  char pdu[64];

  for (int i = 0; i < 5; i++)
    CHECK(e->process_sdu(e, sdu, sizeof(sdu), i, pdu, sizeof(pdu)) > 0);
  nr_pdcp_count_t dl = e->get_pdcp_count_dl(e);
  CHECK(dl.hfn == 0 && dl.sn == 5);

  /* target applies the source's DL COUNT: next SDU must carry exactly that SN */
  nr_pdcp_count_t src_dl = {.sn = 100, .hfn = 3};
  e->set_pdcp_count_dl(e, src_dl, sn_size);
  dl = e->get_pdcp_count_dl(e);
  CHECK(dl.hfn == 3 && dl.sn == 100);
  CHECK(e->process_sdu(e, sdu, sizeof(sdu), 0, pdu, sizeof(pdu)) > 0);
  CHECK(pdu_sn((uint8_t *)pdu, sn_size) == 100);
  dl = e->get_pdcp_count_dl(e);
  CHECK(dl.hfn == 3 && dl.sn == 101);

  /* DL activity must not move the UL COUNT */
  nr_pdcp_count_t ul = e->get_pdcp_count_ul(e);
  CHECK(ul.hfn == 0 && ul.sn == 0);

  e->delete_entity(e);
}

static int build_ul_pdu(uint8_t *out, int sn_size, uint32_t sn, const char *payload, int len)
{
  int h;
  if (sn_size == 12) {
    out[0] = 0x80 | ((sn >> 8) & 0x0f);
    out[1] = sn & 0xff;
    h = 2;
  } else {
    out[0] = 0x80 | ((sn >> 16) & 0x03);
    out[1] = (sn >> 8) & 0xff;
    out[2] = sn & 0xff;
    h = 3;
  }
  memcpy(out + h, payload, len);
  return h + len;
}

static void test_ul_count(int sn_size)
{
  nr_pdcp_entity_t *e = new_drb(sn_size);
  nr_pdcp_count_t src_ul = {.sn = 7, .hfn = 2};
  e->set_pdcp_count_ul(e, src_ul, sn_size);
  nr_pdcp_count_t ul = e->get_pdcp_count_ul(e);
  CHECK(ul.hfn == 2 && ul.sn == 7);
  /* UL activity must not move the DL COUNT */
  nr_pdcp_count_t dl = e->get_pdcp_count_dl(e);
  CHECK(dl.hfn == 0 && dl.sn == 0);

  uint8_t pdu[64];
  /* SN below UL COUNT: already delivered by the source, must be discarded */
  delivered_count = 0;
  int len = build_ul_pdu(pdu, sn_size, 6, "old", 4);
  e->recv_pdu(e, (char *)pdu, len);
  CHECK(delivered_count == 0);

  /* first missing SDU: delivered in sequence, UL COUNT advances */
  len = build_ul_pdu(pdu, sn_size, 7, "new", 4);
  e->recv_pdu(e, (char *)pdu, len);
  CHECK(delivered_count == 1 && strcmp(delivered_buf, "new") == 0);
  ul = e->get_pdcp_count_ul(e);
  CHECK(ul.hfn == 2 && ul.sn == 8);

  e->delete_entity(e);
}

/* DRB PDUs with D/C = 0 are PDCP control PDUs (status report, ROHC feedback): nothing is
 * delivered and the RX state does not move */
static void test_control_pdu(int sn_size)
{
  nr_pdcp_entity_t *e = new_drb(sn_size);
  delivered_count = 0;
  uint8_t status_report[] = {0x00, 0x00, 0x00, 0x00, 0x05, 0xff};
  e->recv_pdu(e, (char *)status_report, sizeof(status_report));
  uint8_t rohc_feedback[] = {0x10, 0x12, 0x34};
  e->recv_pdu(e, (char *)rohc_feedback, sizeof(rohc_feedback));
  uint8_t short_report[] = {0x00, 0x01};
  e->recv_pdu(e, (char *)short_report, sizeof(short_report));
  CHECK(delivered_count == 0);
  nr_pdcp_count_t ul = e->get_pdcp_count_ul(e);
  CHECK(ul.hfn == 0 && ul.sn == 0);

  /* data still goes through */
  uint8_t pdu[16];
  int len = build_ul_pdu(pdu, sn_size, 0, "abc", 4);
  e->recv_pdu(e, (char *)pdu, len);
  CHECK(delivered_count == 1 && strcmp(delivered_buf, "abc") == 0);
  e->delete_entity(e);
}

int main(void)
{
  logInit();
  test_dl_count(12);
  test_dl_count(18);
  test_ul_count(12);
  test_ul_count(18);
  test_control_pdu(12);
  test_control_pdu(18);
  printf("pdcp_count_tests: OK\n");
  return 0;
}
