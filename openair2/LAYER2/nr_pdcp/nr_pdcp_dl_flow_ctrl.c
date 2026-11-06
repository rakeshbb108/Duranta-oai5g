/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include "nr_pdcp_dl_flow_ctrl.h"

#include <stdlib.h>
#include <string.h>
#include "common/utils/assertions.h"
#include "common/utils/utils.h"

static nr_dl_flow_ctrl_config_t fc_config;

void nr_pdcp_dl_flow_ctrl_configure(const nr_dl_flow_ctrl_config_t *config)
{
  fc_config = *config;
}

const nr_dl_flow_ctrl_config_t *nr_pdcp_dl_flow_ctrl_config(void)
{
  return &fc_config;
}

nr_pdcp_dl_fc_t *nr_pdcp_dl_fc_new(uint64_t now)
{
  nr_pdcp_dl_fc_t *fc = calloc_or_fail(1, sizeof(*fc));
  fc->credit = INT64_MAX;
  fc->last_progress = now;
  return fc;
}

static void pop_head(nr_pdcp_dl_fc_t *fc)
{
  nr_pdcp_fc_pdu_t *p = fc->head;
  fc->head = p->next;
  if (fc->head == NULL)
    fc->tail = NULL;
  fc->count--;
  fc->bytes -= p->size;
  free(p);
}

int nr_pdcp_dl_fc_clear(nr_pdcp_dl_fc_t *fc)
{
  int n = fc->count;
  while (fc->head != NULL)
    pop_head(fc);
  return n;
}

void nr_pdcp_dl_fc_free(nr_pdcp_dl_fc_t *fc)
{
  if (fc == NULL)
    return;
  nr_pdcp_dl_fc_clear(fc);
  free(fc);
}

static void send_head(nr_pdcp_dl_fc_t *fc, ue_id_t ue_id, int rb_id, nr_pdcp_fc_send_t send)
{
  nr_pdcp_fc_pdu_t *p = fc->head;
  if (fc->credit != INT64_MAX)
    fc->credit -= p->size;
  send(ue_id, rb_id, p->data, p->size, p->sdu_id);
  pop_head(fc);
}

static void drain(nr_pdcp_dl_fc_t *fc, ue_id_t ue_id, int rb_id, nr_pdcp_fc_send_t send)
{
  while (fc->head != NULL && fc->head->size <= fc->credit)
    send_head(fc, ue_id, rb_id, send);
}

void nr_pdcp_dl_fc_submit(nr_pdcp_dl_fc_t *fc, uint64_t now, ue_id_t ue_id, int rb_id, char *buf, int size, int sdu_id, nr_pdcp_fc_send_t send)
{
  if (fc->head == NULL && size <= fc->credit) {
    if (fc->credit != INT64_MAX)
      fc->credit -= size;
    send(ue_id, rb_id, buf, size, sdu_id);
    return;
  }
  nr_pdcp_fc_pdu_t *p = calloc_or_fail(1, sizeof(*p) + size);
  p->size = size;
  p->sdu_id = sdu_id;
  p->t_held = now;
  memcpy(p->data, buf, size);
  if (fc->tail != NULL)
    fc->tail->next = p;
  else
    fc->head = p;
  fc->tail = p;
  fc->count++;
  fc->bytes += size;
}

void nr_pdcp_dl_fc_set_credit(nr_pdcp_dl_fc_t *fc, uint64_t now, int64_t credit, ue_id_t ue_id, int rb_id, nr_pdcp_fc_send_t send)
{
  fc->credit = credit;
  fc->last_progress = now;
  drain(fc, ue_id, rb_id, send);
}

void nr_pdcp_dl_fc_tick(nr_pdcp_dl_fc_t *fc,
                        uint64_t now,
                        int discard_timer,
                        int stall_timeout_ms,
                        ue_id_t ue_id,
                        int rb_id,
                        nr_pdcp_fc_send_t send)
{
  /* held in arrival order, so the oldest is at the head */
  while (discard_timer >= 0 && fc->head != NULL && now - fc->head->t_held >= (uint64_t)discard_timer) {
    pop_head(fc);
    fc->dropped_expired++;
  }
  if (fc->head == NULL) {
    fc->last_progress = now;
    return;
  }
  if (stall_timeout_ms > 0 && now - fc->last_progress >= (uint64_t)stall_timeout_ms) {
    send_head(fc, ue_id, rb_id, send);
    fc->last_progress = now;
  }
}
