/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "xnap_ids.h"

#include <pthread.h>
#include "ds/hashtable.h"
#include "common/utils/assertions.h"

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
