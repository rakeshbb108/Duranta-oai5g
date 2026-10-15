/*
 * SPDX-License-Identifier: LicenseRef-CSSL-1.0
 */

#include <stdlib.h>
#include <arpa/inet.h>

#include <gtest/gtest.h>

#include "common/platform_types.h"
#include "common/utils/LOG/log.h"
#include "common/config/config_userapi.h"

#include "gtp_itf.h"

extern "C" {
#include "gtpu_extensions.h"

configmodule_interface_t *uniqCfg;

void exit_function(const char *file, const char *function, const int line, const char *s, const int assert)
{
  UNUSED(assert);
  LOG_E(GNB_APP, "error at %s:%d:%s: %s\n", file, line, function, s);
  abort();
}

void *get_softmodem_params(void)
{
  abort();
  return NULL;
};
}

/* @brief initialize GTP interface for IP:port */
static instance_t init_gtp(const char *ip, uint16_t port)
{
  openAddr_t iface = {0};
  DevAssert(strlen(ip) <= sizeof(iface.originHost));
  strcpy(iface.originHost, ip);
  snprintf(iface.originService, sizeof(iface.originService), "%d", port);
  snprintf(iface.destinationService, sizeof(iface.destinationService), "%d", port);
  return gtpv1Init(iface);
}

static in_addr_t get_addr(int ai_family, const char *ip)
{
  AssertFatal(ai_family == AF_INET, "only IPv4 supported\n");
  in_addr_t addr = {0};
  inet_pton(ai_family, ip, &addr);
  return addr;
}

static transport_layer_addr_t get_tl_addr(int ai_family, const char *ip)
{
  in_addr_t addr = get_addr(ai_family, ip);
  transport_layer_addr_t tl_addr = {.length = 32};
  memcpy(tl_addr.buffer, &addr, 4);
  return tl_addr;
}


static void run_basic_test(uint32_t ue_id,
                           long pdu_id,
                           long qfi,
                           int num_send,
                           int *rcv_count,
                           gtpCallback callBack,
                           gtpCallbackSDAP callBackSDAP)
{
  /* set up two instances on different IPs */
  const char *ip1 = "127.0.0.1";
  const char *ip2 = "127.0.0.2";
  uint16_t port = 4567;
  instance_t ep1 = init_gtp(ip1, port);
  EXPECT_GE(ep1, 1);
  instance_t ep2 = init_gtp(ip2, port);
  EXPECT_GE(ep2, 1);
  EXPECT_NE(ep1, ep2); // different IPs => different interfaces

  /* Create receiving end on ep1. Since we don't know the ep2's TEID, we also
   * don't provide an address yet, hence "null_addr". Install the callback
   * specific to this test. */
  transport_layer_addr_t null_addr = {.length = 32};
  teid_t t1 = newGtpuCreateTunnel(ep1, ue_id, pdu_id, pdu_id, -1, null_addr, callBack, callBackSDAP, NULL);

  /* Create the sending end on ep2. We have ep1's address/TEID, so create the
   * remote endpoint. Don't provide a callback, as this is supposed to be
   * unidirectional. */
  transport_layer_addr_t tl_addr1 = get_tl_addr(AF_INET, ip1);
  teid_t t2 = newGtpuCreateTunnel(ep2, ue_id, pdu_id, pdu_id, t1, tl_addr1, NULL, NULL, NULL);

  EXPECT_NE(t1, t2); // cannot be the same TEIDs

  /* With the TEID at ep2, update ep1 endpoint. */
  in_addr_t addr2 = get_addr(AF_INET, ip2);
  GtpuUpdateTunnelOutgoingAddressAndTeid(ep1, ue_id, pdu_id, addr2, t2);

  /* Send num_send messages, with each message three bytes with a specfic
   * payload structure (each byte increasing within the buffer and across
   * message) checked by the callback recv_basic_conn_qfi(). */
  uint8_t buf[3];
  uint8_t payload_counter = 0;
  for (int i = 0; i < num_send; ++i) {
    for (size_t p = 0; p < sizeof(buf); p++)
      buf[p] = payload_counter++;
    if (qfi >= 0)
      gtpv1uSendDirectWithQFI(ep2, ue_id, pdu_id, qfi, buf, sizeof(buf));
    else
      gtpv1uSendDirect(ep2, ue_id, pdu_id, buf, sizeof(buf), false, false);
  }

  usleep(100 * 1000); // wait 100ms to give time to receive packets

  /* check that three messages have been received. The callback checked that
   * the messages had the expected format. */
  EXPECT_EQ(*rcv_count, num_send);

  int ret;
  ret = newGtpuDeleteAllTunnels(ep1, ue_id);
  EXPECT_EQ(ret, 0);
  ret = newGtpuDeleteAllTunnels(ep2, ue_id);
  EXPECT_EQ(ret, 0);

  ret = gtpv1Term(ep1);
  EXPECT_EQ(ret, 0);
  ret = gtpv1Term(ep2);
  EXPECT_EQ(ret, 0);
}

static int recv_count_qfi = 0;
static bool recv_basic_conn_qfi(protocol_ctxt_t *ctxt,
                                const ue_id_t ue_id,
                                const srb_flag_t flag,
                                const mui_t mui,
                                const confirm_t confirm,
                                const sdu_size_t size,
                                unsigned char *const buf,
                                const pdcp_transmission_mode_t modeP,
                                const uint32_t *sourceL2Id,
                                const uint32_t *destinationL2Id,
                                const uint8_t qfi,
                                const bool rqi,
                                const int pdusession_id)
{
  UNUSED(ctxt);
  UNUSED(flag);
  UNUSED(mui);
  UNUSED(confirm);
  UNUSED(modeP);
  UNUSED(sourceL2Id);
  UNUSED(destinationL2Id);
  UNUSED(rqi);
  UNUSED(pdusession_id);
  EXPECT_EQ(ue_id, 1); // as defined in basic_conn_qfi
  EXPECT_EQ(qfi, 1);
  EXPECT_EQ(size, 3);
  for (int i = 0; i < size; ++i)
    EXPECT_EQ(buf[i], recv_count_qfi * size + i);
  recv_count_qfi++;
  LOG_I(GTPU, "received message %d with size 3, content %d.%d.%d\n", recv_count_qfi, buf[0], buf[1], buf[2]);
  return true;
}

static int recv_count_multi_qfi = 0;
static const uint8_t expected_qfis_multi_qfi[] = {1, 5, 9, 5, 1};
static const int expected_qfis_multi_qfi_count = sizeof(expected_qfis_multi_qfi) / sizeof(expected_qfis_multi_qfi[0]);
static bool recv_multi_qfi_same_pdu(protocol_ctxt_t *ctxt,
                                    const ue_id_t ue_id,
                                    const srb_flag_t flag,
                                    const mui_t mui,
                                    const confirm_t confirm,
                                    const sdu_size_t size,
                                    unsigned char *const buf,
                                    const pdcp_transmission_mode_t modeP,
                                    const uint32_t *sourceL2Id,
                                    const uint32_t *destinationL2Id,
                                    const uint8_t qfi,
                                    const bool rqi,
                                    const int pdusession_id)
{
  UNUSED(ctxt);
  UNUSED(flag);
  UNUSED(mui);
  UNUSED(confirm);
  UNUSED(modeP);
  UNUSED(sourceL2Id);
  UNUSED(destinationL2Id);
  UNUSED(rqi);
  EXPECT_EQ(ue_id, 7U);
  EXPECT_EQ(pdusession_id, 9);
  EXPECT_LT(recv_count_multi_qfi, expected_qfis_multi_qfi_count);
  EXPECT_EQ(qfi, expected_qfis_multi_qfi[recv_count_multi_qfi]);
  EXPECT_EQ(size, 3);
  for (int i = 0; i < size; ++i)
    EXPECT_EQ(buf[i], recv_count_multi_qfi * size + i);
  recv_count_multi_qfi++;
  return true;
}

static void run_multi_qos_flows_test(uint32_t ue_id, long pdu_id, const uint8_t *qfis, int num_send)
{
  /* set up two instances on different IPs */
  const char *ip1 = "127.0.0.1";
  const char *ip2 = "127.0.0.2";
  uint16_t port = 4567;
  instance_t ep1 = init_gtp(ip1, port);
  EXPECT_GE(ep1, 1);
  instance_t ep2 = init_gtp(ip2, port);
  EXPECT_GE(ep2, 1);
  EXPECT_NE(ep1, ep2);

  transport_layer_addr_t null_addr = {.length = 32};
  teid_t t1 = newGtpuCreateTunnel(ep1, ue_id, pdu_id, pdu_id, -1, null_addr, NULL, recv_multi_qfi_same_pdu, NULL);

  transport_layer_addr_t tl_addr1 = get_tl_addr(AF_INET, ip1);
  teid_t t2 = newGtpuCreateTunnel(ep2, ue_id, pdu_id, pdu_id, t1, tl_addr1, NULL, NULL, NULL);
  EXPECT_NE(t1, t2);

  in_addr_t addr2 = get_addr(AF_INET, ip2);
  GtpuUpdateTunnelOutgoingAddressAndTeid(ep1, ue_id, pdu_id, addr2, t2);

  uint8_t buf[3];
  uint8_t payload_counter = 0;
  for (int i = 0; i < num_send; ++i) {
    for (size_t p = 0; p < sizeof(buf); p++)
      buf[p] = payload_counter++;
    gtpv1uSendDirectWithQFI(ep2, ue_id, pdu_id, qfis[i], buf, sizeof(buf));
  }

  usleep(100 * 1000);
  EXPECT_EQ(recv_count_multi_qfi, num_send);

  int ret = newGtpuDeleteAllTunnels(ep1, ue_id);
  EXPECT_EQ(ret, 0);
  ret = newGtpuDeleteAllTunnels(ep2, ue_id);
  EXPECT_EQ(ret, 0);
  ret = gtpv1Term(ep1);
  EXPECT_EQ(ret, 0);
  ret = gtpv1Term(ep2);
  EXPECT_EQ(ret, 0);
}

/* Test unidirectional GTP message forwarding for a single UE with QFI. */
TEST(gtp, basic_conn_qfi)
{
  /* we consider only a single UE on a specfic bearer (ID=3) */
  uint32_t ue_id = 1;
  long pdu_id = 3;
  long qfi = 1;
  int num_send = 3;
  run_basic_test(ue_id, pdu_id, qfi, num_send, &recv_count_qfi, NULL, recv_basic_conn_qfi);
}

/* Test one PDU session carrying multiple QoS flows (different QFIs). */
TEST(gtp, multi_qos_flows)
{
  uint32_t ue_id = 7;
  long pdu_id = 9;
  static const uint8_t qfis[] = {1, 5, 9, 5, 1};
  recv_count_multi_qfi = 0;
  run_multi_qos_flows_test(ue_id, pdu_id, qfis, sizeof(qfis) / sizeof(qfis[0]));
}

/* Xn-U DL data forwarding: G-PDUs from gtpv1uSendDirectWithPdcpSn() reach the forwarded-data
 * callback with the PDCP SN of the (Long) PDCP PDU Number extension, or -1 without it, and
 * never the SDAP callback of the tunnel */
static int fwd_recv_count = 0;
static const int fwd_sns[] = {4094, 200000, -1};
static const int fwd_sn_sizes[] = {12, 18, 18};
static void recv_fwd(ue_id_t ue_id, int rb_id, uint8_t *buf, int len, int sn)
{
  UNUSED(ue_id);
  ASSERT_LT(fwd_recv_count, 3);
  EXPECT_EQ(rb_id, 4);
  EXPECT_EQ(len, 2);
  EXPECT_EQ(buf[0], fwd_recv_count);
  EXPECT_EQ(sn, fwd_sns[fwd_recv_count]);
  fwd_recv_count++;
}

static bool recv_fwd_wrong_path(protocol_ctxt_t *ctxt,
                                const ue_id_t ue_id,
                                const srb_flag_t flag,
                                const mui_t mui,
                                const confirm_t confirm,
                                const sdu_size_t size,
                                unsigned char *const buf,
                                const pdcp_transmission_mode_t modeP,
                                const uint32_t *sourceL2Id,
                                const uint32_t *destinationL2Id,
                                const uint8_t qfi,
                                const bool rqi,
                                const int pdusession_id)
{
  UNUSED(ctxt);
  UNUSED(ue_id);
  UNUSED(flag);
  UNUSED(mui);
  UNUSED(confirm);
  UNUSED(size);
  UNUSED(buf);
  UNUSED(modeP);
  UNUSED(sourceL2Id);
  UNUSED(destinationL2Id);
  UNUSED(qfi);
  UNUSED(rqi);
  UNUSED(pdusession_id);
  ADD_FAILURE() << "forwarded SDU delivered to SDAP";
  return true;
}

TEST(gtp, xnu_forwarded_pdcp_sn)
{
  const char *ip1 = "127.0.0.1";
  const char *ip2 = "127.0.0.2";
  uint16_t port = 4567;
  instance_t ep1 = init_gtp(ip1, port);
  instance_t ep2 = init_gtp(ip2, port);
  const uint32_t ue_id = 7;
  const int drb_id = 4;

  transport_layer_addr_t null_addr = {.length = 32};
  teid_t t1 = newGtpuCreateTunnel(ep1, ue_id, drb_id, drb_id, -1, null_addr, NULL, recv_fwd_wrong_path, NULL);
  GtpuSetForwardedDataCallback(t1, recv_fwd);
  transport_layer_addr_t tl_addr1 = get_tl_addr(AF_INET, ip1);
  newGtpuCreateTunnel(ep2, ue_id, drb_id, drb_id, t1, tl_addr1, NULL, NULL, NULL);

  for (int i = 0; i < 3; i++) {
    uint8_t buf[2] = {(uint8_t)i, 0xaa};
    gtpv1uSendDirectWithPdcpSn(ep2, ue_id, drb_id, buf, sizeof(buf), fwd_sns[i], fwd_sn_sizes[i]);
  }
  usleep(100 * 1000);
  EXPECT_EQ(fwd_recv_count, 3);

  EXPECT_EQ(newGtpuDeleteAllTunnels(ep1, ue_id), 0);
  EXPECT_EQ(newGtpuDeleteAllTunnels(ep2, ue_id), 0);
  EXPECT_EQ(gtpv1Term(ep1), 0);
  EXPECT_EQ(gtpv1Term(ep2), 0);
}

/* End Marker: gtpv1uSendEndMarker() reaches the End Marker callback of the receiving
 * tunnel, after the G-PDUs sent before it */
static int em_data_count = 0;
static int em_count = 0;
static void em_recv_fwd(ue_id_t ue_id, int rb_id, uint8_t *buf, int len, int sn)
{
  UNUSED(ue_id);
  UNUSED(rb_id);
  UNUSED(buf);
  UNUSED(len);
  UNUSED(sn);
  EXPECT_EQ(em_count, 0);
  em_data_count++;
}
static void em_recv_end_marker(ue_id_t ue_id, int rb_id)
{
  EXPECT_EQ(ue_id, 9u);
  EXPECT_EQ(rb_id, 3);
  EXPECT_EQ(em_data_count, 2);
  em_count++;
}

TEST(gtp, end_marker_callback)
{
  instance_t ep1 = init_gtp("127.0.0.1", 4567);
  instance_t ep2 = init_gtp("127.0.0.2", 4567);
  const uint32_t ue_id = 9;
  const int drb_id = 3;
  transport_layer_addr_t null_addr = {.length = 32};
  teid_t t1 = newGtpuCreateTunnel(ep1, ue_id, drb_id, drb_id, -1, null_addr, NULL, NULL, NULL);
  GtpuSetForwardedDataCallback(t1, em_recv_fwd);
  GtpuSetEndMarkerCallback(t1, em_recv_end_marker);
  newGtpuCreateTunnel(ep2, ue_id, drb_id, drb_id, t1, get_tl_addr(AF_INET, "127.0.0.1"), NULL, NULL, NULL);

  uint8_t buf[2] = {1, 2};
  gtpv1uSendDirectWithPdcpSn(ep2, ue_id, drb_id, buf, sizeof(buf), 5, 18);
  gtpv1uSendDirectWithPdcpSn(ep2, ue_id, drb_id, buf, sizeof(buf), -1, 18);
  gtpv1uSendEndMarker(ep2, ue_id, drb_id);
  usleep(100 * 1000);
  EXPECT_EQ(em_data_count, 2);
  EXPECT_EQ(em_count, 1);

  EXPECT_EQ(newGtpuDeleteAllTunnels(ep1, ue_id), 0);
  EXPECT_EQ(newGtpuDeleteAllTunnels(ep2, ue_id), 0);
  EXPECT_EQ(gtpv1Term(ep1), 0);
  EXPECT_EQ(gtpv1Term(ep2), 0);
}

static int recv_count = 0;
static bool recv_basic_conn(protocol_ctxt_t *ctxt,
                            const srb_flag_t srb_flagP,
                            const rb_id_t rb_idP,
                            const mui_t muiP,
                            const confirm_t confirmP,
                            const sdu_size_t size,
                            unsigned char *const buf,
                            const pdcp_transmission_mode_t modeP,
                            const uint32_t *sourceL2Id,
                            const uint32_t *destinationL2Id)
{
  UNUSED(srb_flagP);
  UNUSED(rb_idP);
  UNUSED(muiP);
  UNUSED(confirmP);
  UNUSED(modeP);
  UNUSED(sourceL2Id);
  UNUSED(destinationL2Id);
  EXPECT_EQ(ctxt->rntiMaybeUEid, 12); // as defined in basic_conn
  EXPECT_EQ(size, 3);
  for (int i = 0; i < size; ++i)
    EXPECT_EQ(buf[i], recv_count * size + i);
  recv_count++;
  LOG_I(GTPU, "received message %d with size 3, content %d.%d.%d\n", recv_count, buf[0], buf[1], buf[2]);
  return true;
}

/* Test unidirectional GTP message forwarding for a single UE (without QFI). */
TEST(gtp, basic_conn)
{
  /* we consider only a single UE on a specfic bearer (ID=3) */
  uint32_t ue_id = 12;
  long pdu_id = 5;
  long noqfi = -1;
  int num_send = 12;
  run_basic_test(ue_id, pdu_id, noqfi, num_send, &recv_count, recv_basic_conn, NULL);
}

/* F1-U: the CU bearer with a PDCP SN size sets Report Delivered for the SN of the COUNT, the
 * DU tunnel gets it as SN + 1 in the MUI; the DU DL DATA DELIVERY STATUS reaches the CU
 * tunnel's callback with the highest delivered SN */
static mui_t nrup_rx_mui;
static int nrup_rx_count;
static bool nrup_recv_du(protocol_ctxt_t *ctxt,
                         const srb_flag_t flag,
                         const rb_id_t rb_id,
                         const mui_t mui,
                         const confirm_t confirm,
                         const sdu_size_t size,
                         unsigned char *const buf,
                         const pdcp_transmission_mode_t modeP,
                         const uint32_t *sourceL2Id,
                         const uint32_t *destinationL2Id)
{
  UNUSED(ctxt);
  UNUSED(flag);
  UNUSED(rb_id);
  UNUSED(confirm);
  UNUSED(size);
  UNUSED(buf);
  UNUSED(modeP);
  UNUSED(sourceL2Id);
  UNUSED(destinationL2Id);
  nrup_rx_mui = mui;
  nrup_rx_count++;
  return true;
}
static uint32_t nrup_ddds_sn;
static int nrup_ddds_count;
static void nrup_recv_ddds(ue_id_t ue_id, int rb_id, uint32_t highest_delivered_sn)
{
  UNUSED(ue_id);
  EXPECT_EQ(rb_id, 1);
  nrup_ddds_sn = highest_delivered_sn;
  nrup_ddds_count++;
}

TEST(gtp, nrup_report_delivered_and_ddds)
{
  const char *ip_du = "127.0.0.1";
  const char *ip_cu = "127.0.0.2";
  uint16_t port = 4567;
  uint32_t ue_id = 20;
  long drb_id = 1;

  instance_t du = init_gtp(ip_du, port);
  ASSERT_GE(du, 1);
  instance_t cu = init_gtp(ip_cu, port);
  ASSERT_GE(cu, 1);

  transport_layer_addr_t null_addr = {.length = 32};
  teid_t t_du = newGtpuCreateTunnel(du, ue_id, drb_id, drb_id, -1, null_addr, nrup_recv_du, NULL, NULL);
  teid_t t_cu = newGtpuCreateTunnel(cu, ue_id, drb_id, drb_id, t_du, get_tl_addr(AF_INET, ip_du), NULL, NULL, NULL);
  GtpuUpdateTunnelOutgoingAddressAndTeid(du, ue_id, drb_id, get_addr(AF_INET, ip_cu), t_cu);
  GtpuSetPdcpSnSize(cu, ue_id, drb_id, 18);
  GtpuSetDlDeliveryStatusCallback(t_cu, nrup_recv_ddds);

  uint8_t buf[4] = {1, 2, 3, 4};
  gtpv1uSendDirectWithNRUSeqNum(cu, ue_id, drb_id, buf, sizeof(buf), (3u << 18) | 5);
  usleep(100 * 1000);
  EXPECT_EQ(nrup_rx_count, 1);
  EXPECT_EQ(nrup_rx_mui, 5u + 1);

  gtpv1uSendDlDeliveryStatus(du, ue_id, drb_id, 10000, 5);
  usleep(100 * 1000);
  EXPECT_EQ(nrup_ddds_count, 1);
  EXPECT_EQ(nrup_ddds_sn, 5u);

  EXPECT_EQ(newGtpuDeleteAllTunnels(du, ue_id), 0);
  EXPECT_EQ(newGtpuDeleteAllTunnels(cu, ue_id), 0);
  EXPECT_EQ(gtpv1Term(du), 0);
  EXPECT_EQ(gtpv1Term(cu), 0);
}

/** @brief Build a GTPv1-U Error Indication (omit an IE by leaving it zero) */
static size_t build_error_indication(uint8_t *buf, size_t buf_cap, const gtpv1u_error_indication_t *in)
{
  const uint8_t peer_octets = in->gtpu_peer_address.length / 8;
  /** TEID-I (TV): 1 type + 4 value = 5 bytes
   * Peer Address (TLV): 1 type + 2 length + address octets */
  const size_t teid_ie_len = (in->teid_i != 0) ? (1U + GTPU_TEID_I_VALUE_OCTETS) : 0U;
  const size_t peer_ie_len = (peer_octets != 0) ? (1U + 2U + peer_octets) : 0U;
  const size_t ie_len = teid_ie_len + peer_ie_len;
  const size_t body_len = 4U + ie_len; /* optional header (S=1) + IEs */
  const size_t total_len = 8U + body_len; /* mandatory header (8) + payload */

  if (buf_cap < total_len || ie_len == 0)
    return 0;

  uint8_t *p = buf;

  /* Mandatory GTP-U header (8 octets, TS 29.281 clause 5.1 Figure 5.1-1) */
  *p++ = 0x32; /* TS 29.281 clause 5.1: S=1 for Error Indication */
  *p++ = 26; /* Message Type: Error Indication (TS 29.281 Table 6.1-1) */
  *p++ = (body_len >> 8) & 0xff; /* Length (network byte order) */
  *p++ = body_len & 0xff;
  memset(p, 0, 4); /* TEID = 0 (TS 29.281 clause 5.1) */
  p += 4;

  /* Optional GTP-U header fields (4 octets) */
  memset(p, 0, 4); /* Sequence Number, N-PDU Number, Next Extension Header Type */
  p += 4;

  /* Message body: Error Indication IEs (TS 29.281 Table 7.3.1-1) */
  /* TEID-I (TV IE: Type + 4-octet value) */
  if (in->teid_i != 0) {
    *p++ = GTPU_TEID_I;
    uint32_t teid_be = htonl(in->teid_i);
    memcpy(p, &teid_be, sizeof teid_be);
    p += sizeof teid_be;
  }

  /* GTP-U Peer Address (TLV: Type + Length + address octets) */
  if (peer_octets != 0) {
    *p++ = GTPU_PEER_ADDRESS; /* Type */
    *p++ = 0; /* Length (network byte order) */
    *p++ = peer_octets; /* number of address octets */
    memcpy(p, in->gtpu_peer_address.buffer, peer_octets);
    p += peer_octets;
  }

  return total_len;
}

TEST(gtp, error_indication_decode)
{
  uint8_t buf[48] = {0};
  gtpv1u_error_indication_t indication = {0};
  gtpv1u_error_indication_t in = {0};
  size_t len = 0;

  in.gtpu_peer_address = get_tl_addr(AF_INET, "192.168.1.1");

  /* valid mandatory IEs (TEID-I + GTP-U Peer Address) */
  in.teid_i = 0x12345678;
  len = build_error_indication(buf, sizeof buf, &in);
  ASSERT_GT(len, 0U);
  EXPECT_EQ(gtpv1u_decode_error_indication(buf, len, &indication), 0);
  EXPECT_EQ(indication.teid_i, 0x12345678U);
  EXPECT_EQ(indication.gtpu_peer_address.length, 32U);
  EXPECT_EQ(indication.gtpu_peer_address.buffer[0], 192);
  EXPECT_EQ(indication.gtpu_peer_address.buffer[3], 1);

  /* truncation */
  EXPECT_EQ(gtpv1u_decode_error_indication(buf, len - 2, &indication), GTPNOK);

  /* missing mandatory IE (GTP-U Peer Address) */
  in.teid_i = 0x12345678;
  in.gtpu_peer_address.length = 0;
  len = build_error_indication(buf, sizeof buf, &in);
  ASSERT_GT(len, 0U);
  EXPECT_EQ(gtpv1u_decode_error_indication(buf, len, &indication), GTPNOK);

  /* missing mandatory IE (TEID-I) */
  in.teid_i = 0;
  in.gtpu_peer_address = get_tl_addr(AF_INET, "192.168.1.1");
  len = build_error_indication(buf, sizeof buf, &in);
  ASSERT_GT(len, 0U);
  EXPECT_EQ(gtpv1u_decode_error_indication(buf, len, &indication), GTPNOK);

  /* non-zero header TEID */
  in.teid_i = 0x1;
  len = build_error_indication(buf, sizeof buf, &in);
  ASSERT_GT(len, 0U);
  buf[7] = 1;
  EXPECT_EQ(gtpv1u_decode_error_indication(buf, len, &indication), 0);
  EXPECT_EQ(indication.teid_i, 0x1U);
  EXPECT_EQ(indication.gtpu_peer_address.length, 32U);

  /* S=0, 8-byte header (e.g. OAI CN5G UPF): warn and accept */
  static const uint8_t ei_s0[] = {
      0x30, 0x1a, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x00, /* flags S=0, type 26, len 12, TEID 0 */
      0x10, 0x00, 0x00, 0x00, 0x1e, /* TEID-I 0x1e */
      0x85, 0x00, 0x04, 192,  168,  70,   129, /* Peer Address 192.168.70.129 */
  };
  EXPECT_EQ(gtpv1u_decode_error_indication(ei_s0, sizeof ei_s0, &indication), 0);
  EXPECT_EQ(indication.teid_i, 0x1eU);
  EXPECT_EQ(indication.gtpu_peer_address.length, 32U);
  EXPECT_EQ(indication.gtpu_peer_address.buffer[0], 192);
  EXPECT_EQ(indication.gtpu_peer_address.buffer[3], 129);

  /* optional IE present (Recovery Time Stamp) */
  in.teid_i = 0xdeadbeef;
  len = build_error_indication(buf, sizeof buf, &in);
  ASSERT_GT(len, 0U);
  uint8_t *p = buf + len;
  *p++ = GTPU_RECOVERY_TIME_STAMP;
  *p++ = 0;
  *p++ = 4;
  *p++ = 0x12;
  *p++ = 0x34;
  *p++ = 0x56;
  *p++ = 0x78;
  const size_t total_len = p - buf;
  buf[2] = ((total_len - 8) >> 8) & 0xff;
  buf[3] = (total_len - 8) & 0xff;
  EXPECT_EQ(gtpv1u_decode_error_indication(buf, total_len, &indication), 0);
  EXPECT_EQ(indication.teid_i, 0xdeadbeefU);
  EXPECT_EQ(indication.gtpu_peer_address.length, 32U);

  /* E=1 + non-zero header TEID (Open5GS lab): extensions skipped, TEID-I used */
  static const uint8_t ei_with_extensions[] = {
      0x36, 0x1a, 0x00, 0x18, 0x00, 0x00, 0x2c, 0xdf, /* GTP-U: E=1, S=1, type 26, TEID 0x2cdf */
      0x00, 0x00, 0x00, 0x85, /* optional header: Next Ext = PDU Session Container (0x85) */
      0x01, 0x00, 0x01, 0x40, /* ext 0x85, Next Ext = UDP Port (0x40) */
      0x01, 0x00, 0x00, 0x00, /* ext 0x40, Next Ext = none */
      0x10, 0x00, 0x00, 0x2c, 0xdf, /* TEID-I (type 16) */
      0x85, 0x00, 0x04, 192,  168,  71,   1, /* Peer Address (type 133), 192.168.71.1 */
  };
  EXPECT_EQ(gtpv1u_decode_error_indication(ei_with_extensions, sizeof ei_with_extensions, &indication), 0);
  EXPECT_EQ(indication.teid_i, 0x2cdfU);
  EXPECT_EQ(indication.gtpu_peer_address.length, 32U);
  EXPECT_EQ(indication.gtpu_peer_address.buffer[0], 192);
  EXPECT_EQ(indication.gtpu_peer_address.buffer[3], 1);
}

TEST(gtp, error_indication_encode)
{
  uint8_t ie[32] = {0};
  const gtpv1u_error_indication_t in = {.teid_i = 0x12345678, .gtpu_peer_address = get_tl_addr(AF_INET, "10.0.0.1")};

  const int encoded = gtpv1u_encode_error_indication(&in, ie, sizeof ie);
  ASSERT_EQ(encoded, 1 + GTPU_TEID_I_VALUE_OCTETS + 1 + 2 + GTPU_PEER_ADDRESS_IPV4_OCTETS);
  EXPECT_EQ(gtpv1u_encode_error_indication(&in, ie, 4), GTPNOK);

  uint8_t buf[48] = {0};
  const size_t ie_len = 12; /* TEID-I (TV IE) + GTP-U Peer Address (TLV) */
  const size_t body_len = 4U + ie_len; /* optional 4-octet header block (S=1) + IEs */
  const size_t len = 8U + body_len; /* mandatory 8-octet header + body */
  uint8_t *p = buf;
  *p++ = 0x32; /* Flags: version=1, PT=GTP, S=1 (TS 29.281 clause 5.1) */
  *p++ = 26; /* Message Type: Error Indication */
  *p++ = (body_len >> 8) & 0xff; /* Length (network byte order) */
  *p++ = body_len & 0xff;
  memset(p, 0, 4); /* TEID = 0 (TS 29.281 clause 5.1) */
  p += 4;
  memset(p, 0, 4); /* Optional block: Sequence Number, N-PDU Number, Next Extension Header Type */
  p += 4;
  memcpy(p, ie, ie_len); /* TEID-I (TV IE) + GTP-U Peer Address (TLV) */

  gtpv1u_error_indication_t indication = {0};
  EXPECT_EQ(gtpv1u_decode_error_indication(buf, len, &indication), 0);
  EXPECT_EQ(indication.teid_i, in.teid_i);
  EXPECT_EQ(indication.gtpu_peer_address.length, in.gtpu_peer_address.length);
  EXPECT_EQ(memcmp(indication.gtpu_peer_address.buffer, in.gtpu_peer_address.buffer, in.gtpu_peer_address.length / 8), 0);

  uint8_t ie_rt[32] = {0};
  const int encoded_rt = gtpv1u_encode_error_indication(&indication, ie_rt, sizeof ie_rt);
  ASSERT_EQ(encoded_rt, encoded);
  EXPECT_EQ(memcmp(ie, ie_rt, encoded), 0);
}

/* TS 29.281 5.2.2.2: PDCP PDU Number, 15-bit field, 4-octet extension */
TEST(gtp, pdcp_pdu_number_encode)
{
  gtpu_extension_header_t ext = {.type = GTPU_EXT_PDCP_PDU_NUMBER, .pdcp_pdu_number = {.pdcp_pdu_number = 0xabc}};
  uint8_t out[16] = {0};
  ASSERT_EQ(serialize_extension(&ext, GTPU_EXT_NONE, out, sizeof(out)), 4);
  const uint8_t exp[4] = {0x01, 0x0a, 0xbc, 0x00};
  EXPECT_EQ(memcmp(out, exp, sizeof(exp)), 0);
  EXPECT_EQ(serialize_gtpu_extension_type(GTPU_EXT_PDCP_PDU_NUMBER), 0xc0);
}

/* TS 29.281 5.2.2.2A: Long PDCP PDU Number, 18-bit field, 8-octet extension */
TEST(gtp, long_pdcp_pdu_number_encode)
{
  gtpu_extension_header_t ext = {.type = GTPU_EXT_LONG_PDCP_PDU_NUMBER, .pdcp_pdu_number = {.pdcp_pdu_number = 0x3abcd}};
  uint8_t out[16] = {0};
  ASSERT_EQ(serialize_extension(&ext, GTPU_EXT_NONE, out, sizeof(out)), 8);
  const uint8_t exp[8] = {0x02, 0x03, 0xab, 0xcd, 0x00, 0x00, 0x00, 0x00};
  EXPECT_EQ(memcmp(out, exp, sizeof(exp)), 0);
  EXPECT_EQ(serialize_gtpu_extension_type(GTPU_EXT_LONG_PDCP_PDU_NUMBER), 0x82);
}

/* ideas for tests:
 * - share IP addresses among two instances (e.g., F1-U/NG-U on same IP/port)
 * - support of IPv6
 * - test extension headers
 *
 * ideas for cleanup:
 * - simplify callback, harmonize "normal" and "SDAP" callbacks
 * - consistently use either transport_layer_addr_t or in_addr
 */

int main(int argc, char **argv)
{
  //if ((uniqCfg = load_configmodule(argc, argv, CONFIG_ENABLECMDLINEONLY)) == NULL) {
  //  exit_fun("[SOFTMODEM] Error, configuration module init failed\n");
  //}
  // TODO logInit() without config?
  logInit();
  g_log->log_component[GTPU].level = OAILOG_DEBUG;

  testing::InitGoogleTest(&argc, argv);

  return RUN_ALL_TESTS();
}
