/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

/* DU DL delivery tracking for the DL DATA DELIVERY STATUS: only the in-sequence point is
 * reported, every F1U_DL_DELIVERY_REPORT_EVERY PDUs or when nothing is pending */

#include <stdio.h>
#include <stdlib.h>

#include "openair2/LAYER2/NR_MAC_gNB/f1u_dl_delivery.h"
#include "common/utils/LOG/log.h"

#define CHECK(c)                                                             \
  do {                                                                       \
    if (!(c)) {                                                              \
      fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, #c); \
      exit(1);                                                               \
    }                                                                        \
  } while (0)

static int n_reports;
static uint32_t last_ue;
static int last_drb;
static uint32_t last_sn;

static void report(uint32_t ue_id, int drb_id, uint32_t highest_delivered_sn, uint32_t desired_buffer_size)
{
  n_reports++;
  last_ue = ue_id;
  last_drb = drb_id;
  last_sn = highest_delivered_sn;
}

static void test_in_order(void)
{
  n_reports = 0;
  for (uint32_t sn = 0; sn < 40; sn++)
    f1u_dl_delivery_submitted(1, 1, sn);
  for (uint32_t sn = 0; sn < F1U_DL_DELIVERY_REPORT_EVERY - 1; sn++)
    f1u_dl_delivery_delivered(1, 1, sn, 100);
  CHECK(n_reports == 0);
  f1u_dl_delivery_delivered(1, 1, F1U_DL_DELIVERY_REPORT_EVERY - 1, 100);
  CHECK(n_reports == 1 && last_sn == F1U_DL_DELIVERY_REPORT_EVERY - 1 && last_ue == 1 && last_drb == 1);
  for (uint32_t sn = F1U_DL_DELIVERY_REPORT_EVERY; sn < 39; sn++)
    f1u_dl_delivery_delivered(1, 1, sn, 100);
  CHECK(n_reports == 1);
  /* nothing pending anymore: report */
  f1u_dl_delivery_delivered(1, 1, 39, 100);
  CHECK(n_reports == 2 && last_sn == 39);
  f1u_dl_delivery_remove_ue(1);
}

static void test_out_of_order(void)
{
  n_reports = 0;
  for (uint32_t sn = 100; sn < 105; sn++)
    f1u_dl_delivery_submitted(2, 1, sn);
  /* 102 and 103 confirmed while 100 is pending: not in sequence yet */
  f1u_dl_delivery_delivered(2, 1, 102, 100);
  f1u_dl_delivery_delivered(2, 1, 103, 100);
  f1u_dl_delivery_delivered(2, 1, 100, 100);
  CHECK(n_reports == 0);
  f1u_dl_delivery_delivered(2, 1, 101, 100);
  CHECK(n_reports == 0);
  /* SDU without report, or never submitted: ignored */
  f1u_dl_delivery_delivered(2, 1, 7, 100);
  CHECK(n_reports == 0);
  f1u_dl_delivery_delivered(2, 1, 104, 100);
  CHECK(n_reports == 1 && last_sn == 104);
  f1u_dl_delivery_remove_ue(2);
}

static void test_sn_wrap_and_isolation(void)
{
  n_reports = 0;
  f1u_dl_delivery_submitted(3, 1, 262142);
  f1u_dl_delivery_submitted(3, 1, 262143);
  f1u_dl_delivery_submitted(3, 1, 0);
  f1u_dl_delivery_submitted(3, 2, 50);
  f1u_dl_delivery_delivered(3, 1, 262142, 100);
  f1u_dl_delivery_delivered(3, 1, 262143, 100);
  f1u_dl_delivery_delivered(3, 1, 0, 100);
  CHECK(n_reports == 1 && last_sn == 0 && last_drb == 1);
  /* other DRB unaffected, removed UE forgotten */
  f1u_dl_delivery_remove_ue(3);
  f1u_dl_delivery_delivered(3, 2, 50, 100);
  CHECK(n_reports == 1);
}

int main(void)
{
  logInit();
  f1u_dl_delivery_set_report_cb(report);
  test_in_order();
  test_out_of_order();
  test_sn_wrap_and_isolation();
  printf("f1u_dl_delivery_test: OK\n");
  return 0;
}
