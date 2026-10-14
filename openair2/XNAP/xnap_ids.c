/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xnap_ids.h"

#include <stdlib.h>
#include "ds/hashtable.h"
#include "common/utils/assertions.h"
#include "common/utils/LOG/log.h"
#include "common/utils/utils.h"

/* local_xnap_id -> xn_ue_assoc_t (owns the entry) */
static hash_table_t *xn_ue_by_local;
/* rrc_ue_id -> xn_ue_assoc_t (reverse index, bound entries only; does not own) */
static hash_table_t *xn_ue_by_rrc;
static uint32_t xn_next_local_id = 1;

static void xn_ue_nofree(void *p)
{
  (void)p;
}

void xn_ue_init(void)
{
  DevAssert(xn_ue_by_local == NULL && xn_ue_by_rrc == NULL);
  xn_ue_by_local = hashtable_create(1319, NULL, free);
  xn_ue_by_rrc = hashtable_create(1319, NULL, xn_ue_nofree);
  DevAssert(xn_ue_by_local != NULL && xn_ue_by_rrc != NULL);
}

uint32_t xn_ue_alloc_local_id(void)
{
  uint32_t id;
  do {
    id = xn_next_local_id++;
  } while (id == 0 || hashtable_is_key_exists(xn_ue_by_local, id) == HASH_TABLE_OK);
  return id;
}

bool xn_ue_add(const xn_ue_assoc_t *a)
{
  DevAssert(xn_ue_by_local != NULL);
  if (hashtable_is_key_exists(xn_ue_by_local, a->local_xnap_id) == HASH_TABLE_OK)
    return false;
  if (a->rrc_ue_id != XN_UE_RRC_ID_UNBOUND && hashtable_is_key_exists(xn_ue_by_rrc, a->rrc_ue_id) == HASH_TABLE_OK)
    return false;
  xn_ue_assoc_t *stored = malloc_or_fail(sizeof(*stored));
  *stored = *a;
  hashtable_insert(xn_ue_by_local, stored->local_xnap_id, stored);
  if (stored->rrc_ue_id != XN_UE_RRC_ID_UNBOUND)
    hashtable_insert(xn_ue_by_rrc, stored->rrc_ue_id, stored);
  return true;
}

xn_ue_assoc_t *xn_ue_get_by_local(uint32_t local_xnap_id)
{
  void *data = NULL;
  if (hashtable_get(xn_ue_by_local, local_xnap_id, &data) != HASH_TABLE_OK)
    return NULL;
  return data;
}

xn_ue_assoc_t *xn_ue_get_by_rrc(uint32_t rrc_ue_id)
{
  void *data = NULL;
  if (rrc_ue_id == XN_UE_RRC_ID_UNBOUND || hashtable_get(xn_ue_by_rrc, rrc_ue_id, &data) != HASH_TABLE_OK)
    return NULL;
  return data;
}

xn_ue_assoc_t *xn_ue_get_target_by_remote(sctp_assoc_t assoc_id, uint32_t remote_xnap_id)
{
  hash_table_iterator_s it = hashtable_get_iterator(xn_ue_by_local);
  void *data = NULL;
  while (hashtable_iterator_getnext(&it, &data)) {
    xn_ue_assoc_t *a = data;
    if (a->role == XN_ROLE_TARGET && a->assoc_id == assoc_id && a->remote_valid && a->remote_xnap_id == remote_xnap_id)
      return a;
  }
  return NULL;
}

bool xn_ue_bind_rrc(uint32_t local_xnap_id, uint32_t rrc_ue_id)
{
  xn_ue_assoc_t *a = xn_ue_get_by_local(local_xnap_id);
  if (a == NULL || rrc_ue_id == XN_UE_RRC_ID_UNBOUND || a->rrc_ue_id != XN_UE_RRC_ID_UNBOUND)
    return false;
  if (hashtable_is_key_exists(xn_ue_by_rrc, rrc_ue_id) == HASH_TABLE_OK)
    return false;
  a->rrc_ue_id = rrc_ue_id;
  hashtable_insert(xn_ue_by_rrc, rrc_ue_id, a);
  return true;
}

void xn_ue_remove(uint32_t local_xnap_id)
{
  xn_ue_assoc_t *a = xn_ue_get_by_local(local_xnap_id);
  if (a == NULL)
    return;
  if (a->rrc_ue_id != XN_UE_RRC_ID_UNBOUND)
    hashtable_remove(xn_ue_by_rrc, a->rrc_ue_id);
  xnap_ho_timer_untrack(local_xnap_id);
  hashtable_remove(xn_ue_by_local, local_xnap_id);
}

void xn_ue_purge_assoc(sctp_assoc_t assoc_id, void (*on_ue)(const xn_ue_assoc_t *a, void *ctx), void *ctx)
{
  /* collect first: removing while iterating would invalidate the iterator */
  int n = 0;
  hash_table_iterator_s it = hashtable_get_iterator(xn_ue_by_local);
  void *data = NULL;
  while (hashtable_iterator_getnext(&it, &data))
    if (((xn_ue_assoc_t *)data)->assoc_id == assoc_id)
      n++;
  if (n == 0)
    return;

  uint32_t *ids = malloc_or_fail(n * sizeof(*ids));
  int i = 0;
  hash_table_iterator_s it2 = hashtable_get_iterator(xn_ue_by_local);
  while (hashtable_iterator_getnext(&it2, &data) && i < n) {
    const xn_ue_assoc_t *a = data;
    if (a->assoc_id == assoc_id)
      ids[i++] = a->local_xnap_id;
  }

  for (int k = 0; k < i; k++) {
    xn_ue_assoc_t *a = xn_ue_get_by_local(ids[k]);
    if (on_ue != NULL)
      on_ue(a, ctx);
    xn_ue_remove(ids[k]);
  }
  free(ids);
}

/* ------------------------------------------------------------------ */
/* Source-side HO timer roster (bounded array, see XNAP_MAX_HO_TIMERS)  */
/* ------------------------------------------------------------------ */

static uint32_t xnap_ho_timer_ids[XNAP_MAX_HO_TIMERS]; /* 0 = free slot */

void xnap_ho_timer_track(uint32_t local_xnap_id)
{
  for (int i = 0; i < XNAP_MAX_HO_TIMERS; i++) {
    if (xnap_ho_timer_ids[i] == local_xnap_id)
      return; /* already tracked (HO_REQ_SENT -> HO_PREPARED keeps the same slot) */
  }
  for (int i = 0; i < XNAP_MAX_HO_TIMERS; i++) {
    if (xnap_ho_timer_ids[i] == 0) {
      xnap_ho_timer_ids[i] = local_xnap_id;
      return;
    }
  }
  LOG_E(XNAP, "xnap_ho_timer_track: no free slot (XNAP_MAX_HO_TIMERS=%d) for xnap_ue_id %u — guard timer not armed\n",
        XNAP_MAX_HO_TIMERS, local_xnap_id);
}

void xnap_ho_timer_untrack(uint32_t local_xnap_id)
{
  for (int i = 0; i < XNAP_MAX_HO_TIMERS; i++) {
    if (xnap_ho_timer_ids[i] == local_xnap_id) {
      xnap_ho_timer_ids[i] = 0;
      break;
    }
  }
}

int xnap_ho_get_tracked_source_ids(uint32_t out_ids[], int max_ids)
{
  int n = 0;
  for (int i = 0; i < XNAP_MAX_HO_TIMERS && n < max_ids; i++) {
    if (xnap_ho_timer_ids[i] != 0)
      out_ids[n++] = xnap_ho_timer_ids[i];
  }
  return n;
}
