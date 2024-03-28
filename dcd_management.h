#define GET_DCD_INFO_OPCODE 0x5600
typedef struct {
    uint8_t num_host;
    uint8_t num_supported_dc_regions;
    uint16_t rsvd_1;
    uint16_t capacity_selection_policy;
    uint16_t rsvd_2;
    uint16_t capacity_removal_policy;
    uint8_t sanitize_on_release_config_support_mask;
    uint8_t rsvd_3;
    uint64_t total_dyn_cap;
    uint64_t reg_0_supported_block_size_mask;
    uint64_t reg_1_supported_block_size_mask;
    uint64_t reg_2_supported_block_size_mask;
    uint64_t reg_3_supported_block_size_mask;
    uint64_t reg_4_supported_block_size_mask;
    uint64_t reg_5_supported_block_size_mask;
    uint64_t reg_6_supported_block_size_mask;
    uint64_t reg_7_supported_block_size_mask;
}dcd_info_response_payload;