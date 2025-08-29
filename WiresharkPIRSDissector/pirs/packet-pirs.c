#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/dissectors/packet-zbee-aps.h>
#include <glib.h>

#define PIRS_PROFILE_ID 0xC00F

// static uint8_t  number_of_clusters = 8;
// static uint16_t pirs_cluster_id[]  = {0x0301, 0x010B, 0x0117, 0x012D, 0x012E, 0x000E, 0x0001, 0x0107};

static int proto_pirs = -1;
static gint ett_pirs  = -1;

static int
dissect_pirs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_) {
    // if (data) {
    //     zbee_aps_packet *aps_data = (zbee_aps_packet*)data;

    //     if (aps_data->security) {
    //         return 0;
    //     }
    // }
    
    g_print("PIRS dissector called for profile 0x%04X\n", PIRS_PROFILE_ID);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PIRS");
    col_clear(pinfo->cinfo, COL_INFO);

    if (tree) {
        proto_item *ti = NULL;
        proto_tree *pirs_tree = NULL;

        ti = proto_tree_add_item(tree, proto_pirs, tvb, 0, -1, FALSE);
        pirs_tree = proto_item_add_subtree(ti, ett_pirs);
        proto_tree_add_item(pirs_tree, proto_pirs, tvb, 0, 0, FALSE);
    }

    return tvb_reported_length(tvb);
}

void
proto_register_pirs(void) {
    proto_pirs = proto_register_protocol(
        "PIRS Protocol",
        "PIRS",
        "pirs"
    );

    static gint *ett[] = { &ett_pirs };
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_pirs(void) {
    static dissector_handle_t pirs_handle;

    pirs_handle = create_dissector_handle(dissect_pirs, proto_pirs);
    // for (uint8_t cluster_i = 0; cluster_i < number_of_clusters; cluster_i++) {
    //     dissector_add_uint("zbee.zcl.cluster", *(pirs_cluster_id + cluster_i), pirs_handle);
    // }
    dissector_add_uint("zbee.profile", PIRS_PROFILE_ID, pirs_handle);
}