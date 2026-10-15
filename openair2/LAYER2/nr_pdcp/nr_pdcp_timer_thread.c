/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#define _GNU_SOURCE
#include "nr_pdcp_timer_thread.h"

#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>

#include "LOG/log.h"
#include "common/utils/utils.h"

static pthread_mutex_t   timer_thread_mutex   = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t    timer_thread_cond    = PTHREAD_COND_INITIALIZER;
static volatile uint64_t timer_thread_curtime = 0;

static void *nr_pdcp_timer_thread(void *_nr_pdcp_ue_manager)
{
  pthread_setname_np(pthread_self(),"pdcp_timer");
  nr_pdcp_ue_manager_t *nr_pdcp_ue_manager = (nr_pdcp_ue_manager_t *)_nr_pdcp_ue_manager;
  nr_pdcp_ue_t         **ue_list;
  int                  ue_count;
  int                  i;
  int                  j;
  uint64_t             curtime = 0;

  while (1) {
    if (pthread_mutex_lock(&timer_thread_mutex) != 0) abort();
    while (curtime == timer_thread_curtime)
      if (pthread_cond_wait(&timer_thread_cond, &timer_thread_mutex) != 0) abort();
    curtime = timer_thread_curtime;
    if (pthread_mutex_unlock(&timer_thread_mutex) != 0) abort();

    /* Xn HO source forwarding guards expired in this tick, reported after unlocking */
    struct {
      nr_pdcp_forward_timeout_t cb;
      void *data;
      ue_id_t ue_id;
      int rb_id;
    } timeouts[16];
    int n_timeouts = 0;

    nr_pdcp_manager_lock(nr_pdcp_ue_manager);

    ue_list  = nr_pdcp_manager_get_ue_list(nr_pdcp_ue_manager);
    ue_count = nr_pdcp_manager_get_ue_count(nr_pdcp_ue_manager);
    for (i = 0; i < ue_count; i++) {
      for (j = 0; j < 2; j++) {
        if (ue_list[i]->srb[j] != NULL)
          ue_list[i]->srb[j]->set_time(ue_list[i]->srb[j], curtime);
      }
      for (j = 0; j < MAX_DRBS_PER_UE; j++) {
        nr_pdcp_entity_t *drb = ue_list[i]->drb[j];
        if (drb == NULL)
          continue;
        drb->set_time(drb, curtime);
        /* report once; the rest go at the next tick */
        if (drb->forward_timed_out && drb->forward_timeout && n_timeouts < (int)sizeofArray(timeouts)) {
          timeouts[n_timeouts].cb = drb->forward_timeout;
          timeouts[n_timeouts].data = drb->forward_sdu_data;
          timeouts[n_timeouts].ue_id = ue_list[i]->ue_id;
          timeouts[n_timeouts].rb_id = drb->rb_id;
          n_timeouts++;
          drb->forward_timeout = NULL;
        }
      }
    }

    nr_pdcp_manager_unlock(nr_pdcp_ue_manager);

    for (i = 0; i < n_timeouts; i++)
      timeouts[i].cb(timeouts[i].data, timeouts[i].ue_id, timeouts[i].rb_id);
  }

  return NULL;
}

void nr_pdcp_init_timer_thread(nr_pdcp_ue_manager_t *nr_pdcp_ue_manager)
{
  pthread_t t;

  if (pthread_create(&t, NULL, nr_pdcp_timer_thread, nr_pdcp_ue_manager) != 0) {
    LOG_E(PDCP, "%s:%d:%s: fatal\n", __FILE__, __LINE__, __FUNCTION__);
    exit(1);
  }
}

void nr_pdcp_ms_tick(void)
{
  if (pthread_mutex_lock(&timer_thread_mutex)) abort();
  timer_thread_curtime++;
  if (pthread_cond_broadcast(&timer_thread_cond)) abort();
  if (pthread_mutex_unlock(&timer_thread_mutex)) abort();
}

uint64_t nr_pdcp_current_time(void)
{
  return timer_thread_curtime;
}
