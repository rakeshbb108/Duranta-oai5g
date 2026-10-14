/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <stdio.h>
#include <stdint.h>
#include "common/utils/assertions.h"
#include "openair2/XNAP/xnap_ids.h"

static int purged;
static uint32_t purged_rrc_sum;

static void count_purged(const xn_ue_assoc_t *a, void *ctx)
{
  DevAssert(*(int *)ctx == 42);
  purged++;
  purged_rrc_sum += a->rrc_ue_id;
}

int main(void)
{
  xn_ue_init();

  /* allocator: never 0, unique across roles */
  uint32_t s_id = xn_ue_alloc_local_id();
  DevAssert(s_id != 0);
  xn_ue_assoc_t src = {.local_xnap_id = s_id, .rrc_ue_id = 7, .role = XN_ROLE_SOURCE, .assoc_id = 100};
  DevAssert(xn_ue_add(&src));
  DevAssert(!xn_ue_add(&src)); /* duplicate local id */
  uint32_t t_id = xn_ue_alloc_local_id();
  DevAssert(t_id != s_id && t_id != 0);

  /* rrc reverse index */
  DevAssert(xn_ue_get_by_rrc(7) == xn_ue_get_by_local(s_id));
  DevAssert(xn_ue_get_by_rrc(8) == NULL);
  DevAssert(xn_ue_get_by_rrc(XN_UE_RRC_ID_UNBOUND) == NULL);
  xn_ue_assoc_t dup_rrc = {.local_xnap_id = xn_ue_alloc_local_id(), .rrc_ue_id = 7, .role = XN_ROLE_SOURCE};
  DevAssert(!xn_ue_add(&dup_rrc)); /* rrc_ue_id already bound */

  /* pending target entry: found by remote id on its assoc only, bound later */
  xn_ue_assoc_t tgt = {.local_xnap_id = t_id,
                       .remote_xnap_id = 55,
                       .remote_valid = true,
                       .rrc_ue_id = XN_UE_RRC_ID_UNBOUND,
                       .role = XN_ROLE_TARGET,
                       .assoc_id = 100};
  DevAssert(xn_ue_add(&tgt));
  DevAssert(xn_ue_get_target_by_remote(100, 55) == xn_ue_get_by_local(t_id));
  DevAssert(xn_ue_get_target_by_remote(101, 55) == NULL);
  DevAssert(xn_ue_get_target_by_remote(100, 56) == NULL);
  DevAssert(!xn_ue_bind_rrc(t_id, 7)); /* rrc_ue_id 7 taken by the source entry */
  DevAssert(xn_ue_bind_rrc(t_id, 9));
  DevAssert(!xn_ue_bind_rrc(t_id, 10)); /* already bound */
  DevAssert(xn_ue_get_by_rrc(9)->local_xnap_id == t_id);

  /* allocator never hands out an id in use */
  uint32_t next = xn_ue_alloc_local_id();
  DevAssert(xn_ue_get_by_local(next) == NULL);

  /* remove clears both indexes */
  xn_ue_remove(s_id);
  DevAssert(xn_ue_get_by_local(s_id) == NULL && xn_ue_get_by_rrc(7) == NULL);
  xn_ue_remove(s_id); /* idempotent */

  /* purge only the given association */
  xn_ue_assoc_t other = {.local_xnap_id = xn_ue_alloc_local_id(), .rrc_ue_id = 11, .role = XN_ROLE_SOURCE, .assoc_id = 200};
  DevAssert(xn_ue_add(&other));
  xn_ue_assoc_t src2 = {.local_xnap_id = xn_ue_alloc_local_id(), .rrc_ue_id = 12, .role = XN_ROLE_SOURCE, .assoc_id = 100};
  DevAssert(xn_ue_add(&src2));
  int ctx = 42;
  xn_ue_purge_assoc(100, count_purged, &ctx);
  DevAssert(purged == 2 && purged_rrc_sum == 9 + 12);
  DevAssert(xn_ue_get_by_local(t_id) == NULL && xn_ue_get_by_rrc(9) == NULL && xn_ue_get_by_rrc(12) == NULL);
  DevAssert(xn_ue_get_by_rrc(11) != NULL);
  xn_ue_purge_assoc(100, NULL, NULL); /* nothing left */

  /* timer roster: removal untracks */
  xnap_ho_timer_track(other.local_xnap_id);
  uint32_t ids[XNAP_MAX_HO_TIMERS];
  DevAssert(xnap_ho_get_tracked_source_ids(ids, XNAP_MAX_HO_TIMERS) == 1);
  xn_ue_remove(other.local_xnap_id);
  DevAssert(xnap_ho_get_tracked_source_ids(ids, XNAP_MAX_HO_TIMERS) == 0);

  printf("xnap_ids_test: OK\n");
  return 0;
}
