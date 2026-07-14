# Xn-U DL Data Forwarding — Design Reference

**Specifications:** TS 38.423 (XnAP) · TS 38.424/425 (Xn-U) · TS 38.463 (E1AP)

---

## Overview

During Xn-based inter-gNB handover preparation the UE is still attached to the
source while the target gNB is being set up. Downlink packets arriving at the
source UPF for the UE would normally be dropped once the UE disconnects from
the source air interface.

DL data forwarding solves this by pre-allocating a GTP-U tunnel at the
**target** CU-UP during handover preparation. The source CU-UP learns this
tunnel endpoint from the HandoverRequestAcknowledge and begins tunneling
arriving DL packets over Xn-U to the target CU-UP, which buffers and delivers
them to the UE after handover completes. Forwarding continues until HandoverNotify
reaches the UPF and the N3 path switches to the target. An End Marker packet
signals the end of the forwarded stream.

---

## Standards Basis

| Specification | Clause | Relevance |
|---|---|---|
| TS 38.423 | §9.1.1.1 / §9.2.1.1 | XnAP HandoverRequest — `DataforwardingandOffloadingInfofromSource` IE; `dl-forwarding-proposed` per QoS flow |
| TS 38.423 | §9.1.1.2 / §9.2.1.2 | XnAP HandoverRequestAcknowledge — `DataForwardingInfoFromTargetNGRANnode` IE carrying allocated forwarding TEID |
| TS 38.424 / 38.425 | §4 / §5 | Xn-U protocol structure; GTP-U based DL data forwarding between source and target CU-UP |
| TS 38.463 | §8.3.1.2 | E1AP Bearer Context Setup — `Data-Forwarding-Information-Request` requests TEID allocation; `Data-Forwarding-Information` in response carries the allocated TEID |

---

## Deployment Architecture

The DL forwarding logic is identical in both deployment modes because the
`rrc->cucp_cuup.bearer_context_setup` function pointer dispatches appropriately
at runtime.

| Property | Monolithic gNB | CU-CP + CU-UP Split |
|---|---|---|
| CU-UP identity | Virtual entry, `assoc_id = -1` | Real CU-UP, `assoc_id > 0` |
| E1 interface | Direct function call via `cucp_cuup_bearer_context_setup_direct()` | SCTP / E1AP message exchange |
| `ue_associated_to_cuup()` | `true` (checks `e1_assoc_id != 0`; −1 satisfies this) | `true` |
| Registration | `nr-softmodem.c` sends E1AP Setup Req with `originInstance = -1` | CU-UP connects via real SCTP association |

All forwarding logic in `rrc_gNB_process_XNAP_HANDOVER_REQUEST`,
`trigger_bearer_setup`, and `rrc_gNB_send_XNAP_HANDOVER_REQ_ACK` goes through
the same `ue_associated_to_cuup()` + `get_existing_cuup_for_ue()` pattern
established for NGAP-based bearer setup — no special-casing per deployment mode.

---

## End-to-End Message Flow

```
  Source gNB            Target XnAP          Target RRC           Target CU-UP
  (CU-CP/enc.)          (decoder/enc.)        (CU-CP)              (GTP-U/E1AP)
       |                     |                    |                     |
       |--- HandoverRequest ->|                    |                    |
       |  (dataforwarding-   |                    |                    |
       |   infofromSource)   |                    |                    |
       |                     |                    |                    |
       |              decode |-- xnap_handover_req_t (dl_forwarding_proposed=true) ->|
       |                     |                    |                    |
       |                     |                    |--- E1AP BCSetup Req ->|
       |                     |                    |   (dl_fwd_tnl_req=true)          |
       |                     |                    |                    |
       |                     |                    |              xn_gtpu_create()    |
       |                     |                    |              rb_id = pdu_id+128  |
       |                     |                    |                    |
       |                     |                    |<-- E1AP BCSetup Resp ------------|
       |                     |                    |   (dl_fwd_tnl allocated)         |
       |                     |                    |                    |
       |                     |                    | store dl_fwd_cuup_tnl            |
       |                     |                    |                    |
       |                     |<-- HOReqAck data --|                    |
       |                     | (dl_fwd_cuup_tnl)  |                    |
       |                     |                    |                    |
       |<-- HandoverRequestAcknowledge -----------|                    |
       |  (DataForwardingInfo-                    |                    |
       |   FromTargetNGRANnode)                   |                    |
       |                     |                    |                    |
       | store dl_fwd_tnl    |                    |                    |
       | E1AP BearerMod ---> Source CU-UP         |                    |
       | (source CU-UP starts DL forwarding on Xn-U)                  |
```

---

## Implementation Walk-through

### Step 1 — Source encodes DL forwarding proposal

**File:** `openair2/XNAP/lib/xnap_gNB_mobility_management.c`  
**Function:** `encode_xnap_handover_request()`

For every PDU session in the HandoverRequest, the encoder appends a
`dataforwardinginfofromSource` IE with each QoS flow set to
`dl-forwarding-proposed`. This signals to the target that a forwarding TEID is
expected in the HO ACK.

```c
asn1cCalloc(pduItem->dataforwardinginfofromSource, fwdInfo);
for (int j = 0; j < pdu->num_qos; j++) {
  asn1cSequenceAdd(fwdInfo->qosFlowsToBeForwarded.list,
                   XNAP_QoSFLowsToBeForwarded_Item_t, fwdItem);
  fwdItem->qosFlowIdentifier  = pdu->qos_list[j].qfi;
  fwdItem->dl_dataforwarding  = XNAP_DLForwarding_dl_forwarding_proposed;
  fwdItem->ul_dataforwarding  = XNAP_ULForwarding_ul_forwarding_proposed;
}
```

---

### Step 2 — Target XnAP decoder sets dl_forwarding_proposed

**File:** `openair2/XNAP/lib/xnap_gNB_mobility_management.c`  
**Function:** `decode_xnap_handover_request()`

After decoding each PDU session item, the decoder checks whether
`pdu->dataforwardinginfofromSource` is non-NULL and sets
`dst->dl_forwarding_proposed = true` on the internal
`xnap_pdusession_resources_tobe_setup_item_t`.

```c
if (pdu->dataforwardinginfofromSource)
    dst->dl_forwarding_proposed = true;
```

---

### Step 3 — Target RRC propagates flag to pdusession_t

**File:** `openair2/RRC/NR/rrc_gNB_XNAP.c`  
**Function:** `rrc_gNB_process_XNAP_HANDOVER_REQUEST()`

When building the `pdusession_t` array from the XnAP message,
`pdu->dl_forwarding_proposed` is copied from `xpdu->dl_forwarding_proposed`.
This field lives inside `pdusession_t` (not the outer wrapper), so it survives
the `memcpy(&to_setup[n], &pduSession->param, ...)` in `trigger_bearer_setup()`
with no additional plumbing.

```c
pdu->dl_forwarding_proposed = xpdu->dl_forwarding_proposed;
```

---

### Step 4 — E1AP bearer setup request signals TEID allocation

**File:** `openair2/RRC/NR/rrc_gNB_NGAP.c`  
**Function:** `fill_e1_pdusession_to_setup()`

Sets `pdu.dl_fwd_tnl_req = session->dl_forwarding_proposed` before returning.
When true, the E1AP encoder (already implemented in
`openair2/E1AP/lib/e1ap_bearer_context_management.c:422–425`) includes the
`Data-Forwarding-Information-Request` IE in the Bearer Context Setup Request.

```c
pdu.dl_fwd_tnl_req = session->dl_forwarding_proposed;
```

---

### Step 5 — Target CU-UP allocates a distinct forwarding TEID

**File:** `openair2/LAYER2/nr_pdcp/cucp_cuup_handler.c`  
**Functions:** `cucp_cuup_handler_bearer_setup()`, `xn_gtpu_create()`

On seeing `req_pdu->dl_fwd_tnl_req == true`, the handler calls
`xn_gtpu_create(cu_up_ue_id, req_pdu->sessionId)`. The allocated TEID is stored
in `resp_pdu->dl_fwd_tnl` and encoded into the E1AP Bearer Context Setup
Response.

```c
if (req_pdu->dl_fwd_tnl_req) {
    UP_TL_information_t fwd_tl_info = xn_gtpu_create(cu_up_ue_id, req_pdu->sessionId);
    resp_pdu->dl_fwd_tnl = calloc_or_fail(1, sizeof(*resp_pdu->dl_fwd_tnl));
    *resp_pdu->dl_fwd_tnl = fwd_tl_info;
}
```

---

### Step 6 — Target CU-CP stores the forwarding TEID

**File:** `openair2/RRC/NR/rrc_gNB.c`  
**Function:** `rrc_gNB_process_e1_bearer_context_setup_resp()`

If `e1_pdu->dl_fwd_tnl != NULL`, converts it to a `gtpu_tunnel_t` using
`f1u_gtp_update()` and stores it in `rrc_pdu->dl_fwd_cuup_tnl`. This is the
target-side field — distinct from `dl_fwd_tnl` which is used on the source side.

```c
if (e1_pdu->dl_fwd_tnl)
    rrc_pdu->dl_fwd_cuup_tnl = f1u_gtp_update(e1_pdu->dl_fwd_tnl->teId,
                                                e1_pdu->dl_fwd_tnl->tlAddress);
```

---

### Step 7 — Target encodes forwarding TEID in HO ACK

**File:** `openair2/RRC/NR/rrc_gNB_XNAP.c`  
**Function:** `rrc_gNB_send_XNAP_HANDOVER_REQ_ACK()`

`admitted[idx].dl_fwd_tnl` is set from `p->dl_fwd_cuup_tnl`, not from
`p->param.n3_outgoing`. Using `n3_outgoing` would expose the NG-U endpoint and
violate the requirement for a distinct forwarding TEID.

```c
admitted[idx].dl_fwd_tnl = p->dl_fwd_cuup_tnl;
```

---

### Step 8 — Source stores dl_fwd_tnl and activates forwarding

**File:** `openair2/RRC/NR/rrc_gNB_XNAP.c`  
**Function:** `rrc_gNB_process_XNAP_HANDOVER_REQ_ACK()`

On receiving the HO ACK, the source RRC stores the per-session forwarding TEID
in `rrc_pdu->dl_fwd_tnl` (source-side field). It then sends an E1AP Bearer
Context Modification to the source CU-UP containing the target's forwarding TEID
as `pdu_session_to_mod_t.dl_fwd_tnl`. The source CU-UP programs the outgoing
GTP-U tunnel toward the target CU-UP's Xn-U endpoint.

---

## Design Decisions

### GTP-U TEID Namespace Collision

The GTP engine indexes tunnels by `(ue_id, incoming_rb_id)`. Both the N3 NG-U
tunnel and the Xn-U forwarding tunnel belong to the same PDU session and UE, so
naively using `pdusession_id` as `incoming_rb_id` for both causes the second
`gtpv1u_create_ngu_tunnel()` call to overwrite the first — silently destroying
the live N3 session tunnel.

**Solution:** A dedicated `xn_gtpu_create()` function encapsulates the fix. It
uses `incoming_rb_id = pdusession_id + 128`. The offset is an internal invariant
of the function — callers never need to know about it. PDU session IDs are small
integers in practice, so `id + 128` never collides with a real session ID used
as an `incoming_rb_id` elsewhere.

```c
static UP_TL_information_t xn_gtpu_create(uint32_t ue_id, int pdusession_id)
{
    gtpv1u_gnb_create_tunnel_req_t req = {
        .ue_id          = ue_id,
        .pdusession_id  = pdusession_id,
        .incoming_rb_id = pdusession_id + 128,  /* disjoint from N3 NG-U rb_id */
        ...
    };
    ...
}
```

### dl_fwd_cuup_tnl vs. n3_outgoing

The previous HO ACK builder used `p->param.n3_outgoing` (the NG-U GTP endpoint)
as the forwarding TEID. This violates the requirement for a *distinct* forwarding
TEID: the source would send data to the N3/NG-U path, bypassing the dedicated
Xn-U tunnel and causing packet duplication at the UPF.

A separate `dl_fwd_cuup_tnl` field is stored on the target side in
`rrc_pdu_session_param_t`, populated from the E1AP response. The HO ACK builder
reads this field exclusively. The NG-U endpoint (`n3_outgoing`) is never exposed
over Xn as a forwarding address.

### dl_forwarding_proposed placement in pdusession_t

Placing `dl_forwarding_proposed` inside `pdusession_t` (not the outer
`rrc_pdu_session_param_t` wrapper) means the flag survives the
`memcpy(&to_setup[n], &pduSession->param, ...)` in `trigger_bearer_setup()`
without extra plumbing. The flag flows: XnAP decode → RRC → E1AP setup with
zero additional copies.

---

## Key Data Structures

| Field | Type | Struct | Role |
|---|---|---|---|
| `dl_forwarding_proposed` | `bool` | `pdusession_t` (`nr_rrc_defs.h:95`) | Set by target XnAP decoder; read by `fill_e1_pdusession_to_setup()` to set `dl_fwd_tnl_req` |
| `dl_fwd_tnl_req` | `bool` | `pdu_session_to_setup_t` (`e1ap_messages_types.h:449`) | Triggers `Data-Forwarding-Information-Request` IE in E1AP Bearer Context Setup Request |
| `dl_fwd_tnl` | `UP_TL_information_t*` | `pdu_session_setup_t` (`e1ap_messages_types.h:612`) | CU-UP allocated forwarding TEID in E1AP Bearer Context Setup Response |
| `dl_fwd_cuup_tnl` | `gtpu_tunnel_t` | `rrc_pdu_session_param_t` (`nr_rrc_defs.h:106`) | **Target side:** CU-UP's allocated forwarding TEID; used to populate the HO ACK admitted list |
| `dl_fwd_tnl` | `gtpu_tunnel_t` | `rrc_pdu_session_param_t` (`nr_rrc_defs.h:104`) | **Source side:** forwarding TEID received in HO ACK; passed to source CU-UP via E1AP Bearer Context Modification |
| `dl_fwd_tnl` | `gtpu_tunnel_t` | `xnap_pdusession_admitted_item_t` (`xnap_messages_types.h:329`) | Wire representation in XnAP admitted list; zero TEID means forwarding not available |
| `dl_forwarding_proposed` | `bool` | `xnap_pdusession_resources_tobe_setup_item_t` (`xnap_messages_types.h:257`) | Set by decoder when `dataforwardinginfofromSource` IE is present |

---

## Implementation Status

| Phase | Description | Status |
|---|---|---|
| Phase 1 — Signalling | Source proposes forwarding in HandoverRequest; target allocates TEID and returns it in HandoverRequestAcknowledge | ✅ Complete |
| Phase 2 — Source activation | Source CU-CP programs source CU-UP with forwarding TEID via E1AP Bearer Context Modification; source CU-UP opens Xn-U outgoing tunnel | ✅ Complete |
| Phase 3 — End Marker relay | `Gtpv1uHandleEndMarker()` must forward End Marker on the Xn-U tunnel when `dl_fwd_teid != 0`, signalling end of forwarded stream to target CU-UP | ⏳ Pending |
