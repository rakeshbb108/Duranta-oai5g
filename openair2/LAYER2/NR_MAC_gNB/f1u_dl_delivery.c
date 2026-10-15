/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "f1u_dl_delivery.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>

#include "common/utils/LOG/log.h"
#include "common/utils/assertions.h"

#define MAX_TRACKERS 256
/* PDUs tracked per DRB; when full, tracking restarts (nothing is reported for the lost ones) */
#define TRACK_SIZE 16384

typedef struct {
  uint32_t ue_id;
  int drb_id;
  uint32_t sn[TRACK_SIZE];
  bool delivered[TRACK_SIZE];
  int head;
  int count;
  int since_report;
} tracker_t;

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static tracker_t *trackers[MAX_TRACKERS];
static f1u_dl_delivery_report_t report_cb;

void f1u_dl_delivery_set_report_cb(f1u_dl_delivery_report_t cb)
{
  report_cb = cb;
}

static tracker_t *get_tracker(uint32_t ue_id, int drb_id, bool create)
{
  int free_idx = -1;
  for (int i = 0; i < MAX_TRACKERS; i++) {
    tracker_t *t = trackers[i];
    if (t && t->ue_id == ue_id && t->drb_id == drb_id)
      return t;
    if (!t && free_idx < 0)
      free_idx = i;
  }
  if (!create)
    return NULL;
  if (free_idx < 0) {
    LOG_W(NR_MAC, "UE %x DRB %d: no DL delivery tracker left\n", ue_id, drb_id);
    return NULL;
  }
  tracker_t *t = calloc_or_fail(1, sizeof(*t));
  t->ue_id = ue_id;
  t->drb_id = drb_id;
  trackers[free_idx] = t;
  return t;
}

void f1u_dl_delivery_submitted(uint32_t ue_id, int drb_id, uint32_t sn)
{
  pthread_mutex_lock(&mutex);
  tracker_t *t = get_tracker(ue_id, drb_id, true);
  if (t) {
    if (t->count == TRACK_SIZE) {
      LOG_W(NR_MAC, "UE %x DRB %d: %d PDUs pending delivery, restarting DL delivery tracking\n", ue_id, drb_id, TRACK_SIZE);
      t->head = t->count = t->since_report = 0;
    }
    int i = (t->head + t->count) % TRACK_SIZE;
    t->sn[i] = sn;
    t->delivered[i] = false;
    t->count++;
  }
  pthread_mutex_unlock(&mutex);
}

void f1u_dl_delivery_delivered(uint32_t ue_id, int drb_id, uint32_t sn, uint32_t desired_buffer_size)
{
  bool report = false;
  uint32_t highest = 0;
  pthread_mutex_lock(&mutex);
  tracker_t *t = get_tracker(ue_id, drb_id, false);
  if (t) {
    for (int k = 0; k < t->count; k++) {
      int i = (t->head + k) % TRACK_SIZE;
      if (t->sn[i] == sn && !t->delivered[i]) {
        t->delivered[i] = true;
        break;
      }
    }
    bool advanced = false;
    while (t->count > 0 && t->delivered[t->head]) {
      highest = t->sn[t->head];
      t->head = (t->head + 1) % TRACK_SIZE;
      t->count--;
      t->since_report++;
      advanced = true;
    }
    if (advanced && (t->since_report >= F1U_DL_DELIVERY_REPORT_EVERY || t->count == 0)) {
      t->since_report = 0;
      report = true;
    }
  }
  pthread_mutex_unlock(&mutex);
  if (report && report_cb)
    report_cb(ue_id, drb_id, highest, desired_buffer_size);
}

void f1u_dl_delivery_remove_ue(uint32_t ue_id)
{
  pthread_mutex_lock(&mutex);
  for (int i = 0; i < MAX_TRACKERS; i++) {
    if (trackers[i] && trackers[i]->ue_id == ue_id) {
      free(trackers[i]);
      trackers[i] = NULL;
    }
  }
  pthread_mutex_unlock(&mutex);
}
