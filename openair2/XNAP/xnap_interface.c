/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <stdlib.h>
#include <string.h>
#include "common/utils/LOG/log.h"
#include "openair2/GNB_APP/gnb_paramdef.h"
#include "openair2/COMMON/ngap_messages_types.h"
#include "openair2/COMMON/xnap_messages_types.h"
#include "openair3/SCTP/sctp_default_values.h"

xnap_setup_info_t Read_Xn_Setup_Info(const ngap_register_gnb_cnf_t *cnf, uint32_t gnb_idx)
{
  LOG_I(XNAP, "[gNB %u] Reading Xn setup info from NGAP_REGISTER_GNB_CNF\n", gnb_idx);
  xnap_setup_info_t setup_info = {0};

  setup_info.gNB_id = cnf->gNB_id;
  if (cnf->num_plmn > 0)
    setup_info.plmn = cnf->plmn[0].plmn;

  setup_info.num_tai = 1;
  setup_info.tai_support = calloc(setup_info.num_tai, sizeof(*setup_info.tai_support));

  for (int i = 0; i < setup_info.num_tai; i++) {
    setup_info.tai_support[i].tac = cnf->tac;
    setup_info.tai_support[i].num_plmn = cnf->num_plmn;
    setup_info.tai_support[i].plmn_support = calloc(cnf->num_plmn, sizeof(*setup_info.tai_support[i].plmn_support));

    for (int j = 0; j < cnf->num_plmn; j++) {
      setup_info.tai_support[i].plmn_support[j].plmn = cnf->plmn[j].plmn;
      setup_info.tai_support[i].plmn_support[j].num_nssai = cnf->plmn[j].num_nssai;
      setup_info.tai_support[i].plmn_support[j].nssai =
          calloc(cnf->plmn[j].num_nssai, sizeof(*setup_info.tai_support[i].plmn_support[j].nssai));

      for (int k = 0; k < cnf->plmn[j].num_nssai; k++)
        setup_info.tai_support[i].plmn_support[j].nssai[k] = cnf->plmn[j].s_nssai[k];
    }
  }

  setup_info.num_amf_regions = cnf->num_amf_regions;
  if (cnf->num_amf_regions > 0) {
    setup_info.amf_region_info = calloc(cnf->num_amf_regions, sizeof(*setup_info.amf_region_info));
    for (int r = 0; r < cnf->num_amf_regions; r++) {
      setup_info.amf_region_info[r].plmn = cnf->amf_region_info[r].plmn;
      setup_info.amf_region_info[r].amf_region_id = cnf->amf_region_info[r].amf_region_id;
    }
  }

  return setup_info;
}

xnap_net_config_t Read_IPconfig_Xn(uint32_t gnb_idx)
{
  xnap_net_config_t nc = {0};
  paramdef_t XnCandidateParams[] = XN_CANDIDATE_PARAMS_DESC;
  paramlist_def_t XnCandidateList = {GNB_CONFIG_STRING_XN_CANDIDATES, NULL, 0};
  paramdef_t SCTPParams[] = GNBSCTPPARAMS_DESC;
  char aprefix[MAX_OPTNAME_SIZE * 2 + 8];

  sprintf(aprefix, "%s.[%u].%s", GNB_CONFIG_STRING_GNB_LIST, gnb_idx, GNB_CONFIG_STRING_XNAP);
  config_getlist(config_get_if(), &XnCandidateList, XnCandidateParams, sizeofArray(XnCandidateParams), aprefix);

  AssertFatal(XnCandidateList.numelt <= MAX_XNAP_PEERS,
              "value of XnCandidateList.numelt %d must be lower than MAX_XNAP_PEERS %d value\n",
              XnCandidateList.numelt,
              MAX_XNAP_PEERS);

  LOG_I(XNAP, "Number of candidate gNBs configured: %d\n", XnCandidateList.numelt);

  for (int l = 0; l < XnCandidateList.numelt; l++) {
    nc.nb_of_candidate_gNBs++;
    nc.candidate_gnb_xn_ip_address[l] = strdup(*(XnCandidateList.paramarray[l][GNB_CONFIG_STRING_CANDIDATE_GNB_XN_IP_ADDRESS_IDX].strptr));
    LOG_I(XNAP, "Candidate gNB %d: %s\n", l + 1, nc.candidate_gnb_xn_ip_address[l]); 
  }

  paramdef_t XnParams[] = XnPARAMS_DESC;
  config_get(config_get_if(), XnParams, sizeofArray(XnParams), aprefix);

  nc.gnb_port_for_xnc = (uint32_t)*(XnParams[GNB_CONFIG_STRING_GNB_PORT_FOR_XNC_IDX].uptr);

  AssertFatal(XnParams[GNB_CONFIG_STRING_GNB_IP_ADDR_FOR_XNC_IDX].strptr != NULL && nc.gnb_port_for_xnc != 0,
              "gNB Xn Interface IP/Port not configured\n");

  nc.gnb_xn_interface_ip_address = strdup(*(XnParams[GNB_CONFIG_STRING_GNB_IP_ADDR_FOR_XNC_IDX].strptr));

  nc.sctp_streams.sctp_out_streams = SCTP_OUT_STREAMS;
  nc.sctp_streams.sctp_in_streams = SCTP_IN_STREAMS;

  sprintf(aprefix, "%s.[%u].%s", GNB_CONFIG_STRING_GNB_LIST, gnb_idx, GNB_CONFIG_STRING_SCTP_CONFIG);
  config_get(config_get_if(), SCTPParams, sizeofArray(SCTPParams), aprefix);

  nc.sctp_streams.sctp_in_streams = (uint16_t)*(SCTPParams[GNB_SCTP_INSTREAMS_IDX].uptr);
  nc.sctp_streams.sctp_out_streams = (uint16_t)*(SCTPParams[GNB_SCTP_OUTSTREAMS_IDX].uptr);

  return nc;
}

int is_xnap_enabled(void){
  char xn_path[MAX_OPTNAME_SIZE * 2 + 8];
  snprintf(xn_path, sizeof(xn_path), "%s.[%d].%s", GNB_CONFIG_STRING_GNB_LIST, 0, GNB_CONFIG_STRING_XNAP);
  paramdef_t Xn_Params[] = XnPARAMS_DESC;
  config_get(config_get_if(), Xn_Params, sizeofArray(Xn_Params), xn_path);
  int xn_enabled = *(Xn_Params[GNB_CONFIG_XNAP_ENABLE_IDX].iptr);
  LOG_D(XNAP, "Reading XNAP config from %s\n", xn_path);
  LOG_I(XNAP, "XnAP interface %s\n", xn_enabled ? "enabled" : "disabled");

  return xn_enabled;
}
