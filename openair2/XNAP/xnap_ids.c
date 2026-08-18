/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xnap_ids.h"

#include <pthread.h>
#include "ds/hashtable.h"
#include "common/utils/assertions.h"
#include "common/utils/LOG/log.h"

/* Source-side table: s_ng_node_ue_xnap_id → xnap_ue_data_t */
static hash_table_t    *xnap_ue_mapping;
static pthread_mutex_t  xnap_ue_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t         xnap_next_ue_id = 1;

/* Target-side table: t_ng_node_ue_xnap_id → xnap_target_ue_data_t */
static hash_table_t    *xnap_target_ue_mapping;
static pthread_mutex_t  xnap_target_ue_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint32_t         xnap_next_target_ue_id = 1;

void xnap_init_ue_data(void)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping == NULL);
  xnap_ue_mapping = hashtable_create(1319, NULL, free);
  DevAssert(xnap_ue_mapping != NULL);
  pthread_mutex_unlock(&xnap_ue_mutex);

  pthread_mutex_lock(&xnap_target_ue_mutex);
  DevAssert(xnap_target_ue_mapping == NULL);
  xnap_target_ue_mapping = hashtable_create(1319, NULL, free);
  DevAssert(xnap_target_ue_mapping != NULL);
  pthread_mutex_unlock(&xnap_target_ue_mutex);
}

uint32_t xnap_alloc_ue_id(void)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  uint32_t id = xnap_next_ue_id++;
  pthread_mutex_unlock(&xnap_ue_mutex);
  return id;
}

bool xnap_add_ue_data(uint32_t xnap_ue_id, const xnap_ue_data_t *data)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  if (hashtable_is_key_exists(xnap_ue_mapping, xnap_ue_id) == HASH_TABLE_OK) {
    pthread_mutex_unlock(&xnap_ue_mutex);
    return false;
  }
  xnap_ue_data_t *stored = malloc(sizeof(*stored));
  AssertFatal(stored != NULL, "cannot allocate xnap_ue_data_t\n");
  *stored = *data;
  hashtable_rc_t rc = hashtable_insert(xnap_ue_mapping, xnap_ue_id, stored);
  pthread_mutex_unlock(&xnap_ue_mutex);
  return rc == HASH_TABLE_OK;
}

bool xnap_exists_ue_data(uint32_t xnap_ue_id)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  hashtable_rc_t rc = hashtable_is_key_exists(xnap_ue_mapping, xnap_ue_id);
  pthread_mutex_unlock(&xnap_ue_mutex);
  return rc == HASH_TABLE_OK;
}

xnap_ue_data_t xnap_get_ue_data(uint32_t xnap_ue_id)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  void *data = NULL;
  hashtable_rc_t rc = hashtable_get(xnap_ue_mapping, xnap_ue_id, &data);
  AssertFatal(rc == HASH_TABLE_OK && data != NULL,
              "xnap_ue_id %u not found in UE mapping\n", xnap_ue_id);
  xnap_ue_data_t result = *(xnap_ue_data_t *)data;
  pthread_mutex_unlock(&xnap_ue_mutex);
  return result;
}

bool xnap_remove_ue_data(uint32_t xnap_ue_id)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  hashtable_rc_t rc = hashtable_remove(xnap_ue_mapping, xnap_ue_id);
  pthread_mutex_unlock(&xnap_ue_mutex);
  return rc == HASH_TABLE_OK;
}

bool xnap_set_ue_target_id(uint32_t xnap_ue_id, uint32_t t_xnap_ue_id)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  void *data = NULL;
  hashtable_rc_t rc = hashtable_get(xnap_ue_mapping, xnap_ue_id, &data);
  if (rc == HASH_TABLE_OK && data != NULL)
    ((xnap_ue_data_t *)data)->t_ng_node_ue_xnap_id = t_xnap_ue_id;
  pthread_mutex_unlock(&xnap_ue_mutex);
  return rc == HASH_TABLE_OK && data != NULL;
}

bool xnap_set_ue_sm_state(uint32_t xnap_ue_id, xnap_ho_src_state_t state)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  void *data = NULL;
  hashtable_rc_t rc = hashtable_get(xnap_ue_mapping, xnap_ue_id, &data);
  if (rc == HASH_TABLE_OK && data != NULL)
    ((xnap_ue_data_t *)data)->sm_state = state;
  pthread_mutex_unlock(&xnap_ue_mutex);
  return rc == HASH_TABLE_OK && data != NULL;
}

bool xnap_set_ue_timer_mark_relocprep(uint32_t xnap_ue_id, uint64_t now)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  void *data = NULL;
  hashtable_rc_t rc = hashtable_get(xnap_ue_mapping, xnap_ue_id, &data);
  if (rc == HASH_TABLE_OK && data != NULL)
    xnap_ho_src_set_relocprep_start(&((xnap_ue_data_t *)data)->timer_marks, now);
  pthread_mutex_unlock(&xnap_ue_mutex);
  return rc == HASH_TABLE_OK && data != NULL;
}

bool xnap_set_ue_timer_mark_relocoverall(uint32_t xnap_ue_id, uint64_t now)
{
  pthread_mutex_lock(&xnap_ue_mutex);
  DevAssert(xnap_ue_mapping != NULL);
  void *data = NULL;
  hashtable_rc_t rc = hashtable_get(xnap_ue_mapping, xnap_ue_id, &data);
  if (rc == HASH_TABLE_OK && data != NULL)
    xnap_ho_src_set_relocoverall_start(&((xnap_ue_data_t *)data)->timer_marks, now);
  pthread_mutex_unlock(&xnap_ue_mutex);
  return rc == HASH_TABLE_OK && data != NULL;
}

/* ------------------------------------------------------------------ */
/* Source-side HO timer roster (bounded array, see XNAP_MAX_HO_TIMERS)  */
/* ------------------------------------------------------------------ */

static uint32_t        xnap_ho_timer_ids[XNAP_MAX_HO_TIMERS]; /* 0 = free slot */
static pthread_mutex_t xnap_ho_timer_mutex = PTHREAD_MUTEX_INITIALIZER;

void xnap_ho_timer_track(uint32_t xnap_ue_id)
{
  pthread_mutex_lock(&xnap_ho_timer_mutex);
  for (int i = 0; i < XNAP_MAX_HO_TIMERS; i++) {
    if (xnap_ho_timer_ids[i] == xnap_ue_id) {
      pthread_mutex_unlock(&xnap_ho_timer_mutex);
      return; /* already tracked (HO_REQ_SENT -> HO_PREPARED keeps the same slot) */
    }
  }
  for (int i = 0; i < XNAP_MAX_HO_TIMERS; i++) {
    if (xnap_ho_timer_ids[i] == 0) {
      xnap_ho_timer_ids[i] = xnap_ue_id;
      pthread_mutex_unlock(&xnap_ho_timer_mutex);
      return;
    }
  }
  pthread_mutex_unlock(&xnap_ho_timer_mutex);
  LOG_E(XNAP, "xnap_ho_timer_track: no free slot (XNAP_MAX_HO_TIMERS=%d) for xnap_ue_id %u — guard timer not armed\n",
        XNAP_MAX_HO_TIMERS, xnap_ue_id);
}

void xnap_ho_timer_untrack(uint32_t xnap_ue_id)
{
  pthread_mutex_lock(&xnap_ho_timer_mutex);
  for (int i = 0; i < XNAP_MAX_HO_TIMERS; i++) {
    if (xnap_ho_timer_ids[i] == xnap_ue_id) {
      xnap_ho_timer_ids[i] = 0;
      break;
    }
  }
  pthread_mutex_unlock(&xnap_ho_timer_mutex);
}

int xnap_ho_get_tracked_source_ids(uint32_t out_ids[], int max_ids)
{
  int n = 0;
  pthread_mutex_lock(&xnap_ho_timer_mutex);
  for (int i = 0; i < XNAP_MAX_HO_TIMERS && n < max_ids; i++) {
    if (xnap_ho_timer_ids[i] != 0)
      out_ids[n++] = xnap_ho_timer_ids[i];
  }
  pthread_mutex_unlock(&xnap_ho_timer_mutex);
  return n;
}

/* ------------------------------------------------------------------ */
/* Target-side table                                                    */
/* ------------------------------------------------------------------ */

uint32_t xnap_alloc_target_ue_id(void)
{
  pthread_mutex_lock(&xnap_target_ue_mutex);
  uint32_t id = xnap_next_target_ue_id++;
  pthread_mutex_unlock(&xnap_target_ue_mutex);
  return id;
}

bool xnap_add_target_ue_data(uint32_t t_xnap_ue_id, const xnap_target_ue_data_t *data)
{
  pthread_mutex_lock(&xnap_target_ue_mutex);
  DevAssert(xnap_target_ue_mapping != NULL);
  if (hashtable_is_key_exists(xnap_target_ue_mapping, t_xnap_ue_id) == HASH_TABLE_OK) {
    pthread_mutex_unlock(&xnap_target_ue_mutex);
    return false;
  }
  xnap_target_ue_data_t *stored = malloc(sizeof(*stored));
  AssertFatal(stored != NULL, "cannot allocate xnap_target_ue_data_t\n");
  *stored = *data;
  hashtable_rc_t rc = hashtable_insert(xnap_target_ue_mapping, t_xnap_ue_id, stored);
  pthread_mutex_unlock(&xnap_target_ue_mutex);
  return rc == HASH_TABLE_OK;
}

bool xnap_exists_target_ue_data(uint32_t t_xnap_ue_id)
{
  pthread_mutex_lock(&xnap_target_ue_mutex);
  DevAssert(xnap_target_ue_mapping != NULL);
  hashtable_rc_t rc = hashtable_is_key_exists(xnap_target_ue_mapping, t_xnap_ue_id);
  pthread_mutex_unlock(&xnap_target_ue_mutex);
  return rc == HASH_TABLE_OK;
}

xnap_target_ue_data_t xnap_get_target_ue_data(uint32_t t_xnap_ue_id)
{
  pthread_mutex_lock(&xnap_target_ue_mutex);
  DevAssert(xnap_target_ue_mapping != NULL);
  void *data = NULL;
  hashtable_rc_t rc = hashtable_get(xnap_target_ue_mapping, t_xnap_ue_id, &data);
  AssertFatal(rc == HASH_TABLE_OK && data != NULL,
              "t_xnap_ue_id %u not found in target UE mapping\n", t_xnap_ue_id);
  xnap_target_ue_data_t result = *(xnap_target_ue_data_t *)data;
  pthread_mutex_unlock(&xnap_target_ue_mutex);
  return result;
}

bool xnap_remove_target_ue_data(uint32_t t_xnap_ue_id)
{
  pthread_mutex_lock(&xnap_target_ue_mutex);
  DevAssert(xnap_target_ue_mapping != NULL);
  hashtable_rc_t rc = hashtable_remove(xnap_target_ue_mapping, t_xnap_ue_id);
  pthread_mutex_unlock(&xnap_target_ue_mutex);
  return rc == HASH_TABLE_OK;
}

xnap_target_ue_data_t *xnap_find_target_ue_by_source_id(uint32_t s_xnap_ue_id, uint32_t *t_xnap_ue_id)
{
  xnap_target_ue_data_t *found = NULL;
  pthread_mutex_lock(&xnap_target_ue_mutex);
  DevAssert(xnap_target_ue_mapping != NULL);
  for (hash_size_t i = 0; i < xnap_target_ue_mapping->size && !found; i++) {
    for (hash_node_t *node = xnap_target_ue_mapping->nodes[i]; node != NULL; node = node->next) {
      xnap_target_ue_data_t *entry = node->data;
      if (entry->s_ng_node_ue_xnap_id == s_xnap_ue_id) {
        *t_xnap_ue_id = (uint32_t)node->key;
        found = entry;
        break;
      }
    }
  }
  pthread_mutex_unlock(&xnap_target_ue_mutex);
  return found;
}

bool xnap_set_target_ue_sm_state(uint32_t t_xnap_ue_id, xnap_ho_tgt_state_t state)
{
  pthread_mutex_lock(&xnap_target_ue_mutex);
  DevAssert(xnap_target_ue_mapping != NULL);
  void *data = NULL;
  hashtable_rc_t rc = hashtable_get(xnap_target_ue_mapping, t_xnap_ue_id, &data);
  if (rc == HASH_TABLE_OK && data != NULL)
    ((xnap_target_ue_data_t *)data)->sm_state = state;
  pthread_mutex_unlock(&xnap_target_ue_mutex);
  return rc == HASH_TABLE_OK && data != NULL;
}
