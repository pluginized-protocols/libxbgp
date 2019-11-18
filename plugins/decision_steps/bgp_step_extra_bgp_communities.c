//
// Created by thomas on 20/03/19.
//

#include <ubpf_tools/include/public_bpf.h>
#include <bgpd/bgp_ubpf_api_plugins.h>
#include <bgpd/bgp_community.h>

#define ORGININATED_AS(community) ((community >> 16u) & 0xFFFFu)
#define COMMUNITY_VALUE(community) (community & 0xFFFFu)

#define RESERVED_AS_WELL_KNOWN 0xFFFF
#define RESERVED_AS_NULL_AS 0x0000

#define MY_LOCATION BRUSSELS

typedef struct coord {
    long latitude;
    long longitude;
} coord_t;

typedef enum LOCATION {
    BRUSSELS = 1,
    PARIS,
    NY
} location_t;

static const struct coordinate_map_id {

    location_t loc;
    long latitude;
    long longitude;

} map_conv[] = {
        {BRUSSELS, 1, 1},
        {PARIS,    0, 1},
        {NY,       1, 1}
};

static inline long math_abs(long x) {
    return x < 0 ? -x : x;
}

static inline int is_reserved(uint32_t asn) {
    return asn != RESERVED_AS_WELL_KNOWN &&
           asn != RESERVED_AS_NULL_AS;
}

static inline unsigned int is_geo_loc(uint16_t community_val) {
    return (community_val >> 15u) & 1u;
}

static inline uint16_t get_geo_length(const uint32_t *vals, size_t len) {
    size_t i;
    uint32_t cm;
    uint16_t originated_as, community_value;

    for (i = 0; i < len; i++) {
        cm = vals[i];

        originated_as = (uint16_t) ORGININATED_AS(cm);
        community_value = (uint16_t) COMMUNITY_VALUE(cm);

        if (!is_reserved(originated_as) && is_geo_loc(community_value)) {
            return community_value & ((uint16_t) 0x7fff);
        }
    }

    return 0;

}

static inline coord_t get_info_coord(location_t loc) {

    size_t i;
    coord_t coord;
    memset(&coord, 0, sizeof(coord_t));
    size_t size = sizeof(map_conv) / sizeof(map_conv[0]);

    for (i = 0; i < size; i++) {
        if (map_conv[i].loc == loc) {

            coord.latitude = map_conv[i].latitude;
            coord.longitude = map_conv[i].longitude;

            return coord;
        }
    }

    return coord;

}

static inline int location_cmp(location_t new, location_t old) {
    coord_t my_coord;
    coord_t new_coord;
    coord_t old_coord;

    long dist_new, dist_old;

    my_coord = get_info_coord(MY_LOCATION);
    new_coord = get_info_coord(new);
    old_coord = get_info_coord(old);

    if ((new_coord.latitude == 0 && new_coord.longitude == 0) ||
        (old_coord.latitude == 0 && old_coord.longitude == 0))
        return BGP_DECISION_WEIGHT; // no info of this coordinate --> skip and go to next step


    dist_new = math_abs(new_coord.longitude - my_coord.longitude) + math_abs(new_coord.latitude - my_coord.latitude);
    dist_old = math_abs(old_coord.longitude - my_coord.longitude) + math_abs(old_coord.latitude - my_coord.latitude);


    if (dist_new > dist_old) return BGP_SPEC_COMP_1;
    if (dist_new < dist_old) return BGP_SPEC_COMP_2;

    return BGP_DECISION_WEIGHT;

}

#define cleanup \
ctx_free(new_community);\
ctx_free(old_community);\
ctx_free(val_new_community);\
ctx_free(val_old_community);

int bgp_communities_cmp(bpf_full_args_t *args) {

    struct community *new_community;
    struct community *old_community;

    uint32_t *val_new_community = NULL;
    uint32_t *val_old_community = NULL;

    uint16_t old_location;
    uint16_t new_location;

    int ret_val;

    new_community = get_community_from_path_info(args, 2);
    old_community = get_community_from_path_info(args, 1);

    if (!new_community || ! old_community) {
        cleanup
        return BGP_SPEC_ERROR;
    }

    val_new_community = get_community_values_from_path_info(args, 2);
    val_old_community = get_community_values_from_path_info(args, 1);

    if(!val_new_community || !val_old_community){
        cleanup
        return BGP_SPEC_ERROR;
    }

    old_location = get_geo_length(val_old_community, old_community->size);
    new_location = get_geo_length(val_new_community, new_community->size);

    ret_val = location_cmp(new_location, old_location);

    cleanup
    return ret_val;

}