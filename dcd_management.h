#ifndef DCD_MANAGEMENT_H
#define DCD_MANAGEMENT_H
#define GET_DCD_INFO_OPCODE 0x5600
#define GET_HOST_DC_REGION_CONFIG_OPCODE 0x5601
#define SET_DC_REGION_CONFIG_OPCODE 0x5602
#define GET_DC_REGION_EXTENT_LISTS_OPCODE 0x5603
#define INITIATE_DYNAMIC_CAPACITY_ADD_OPCODE 0x5604
#define INITIATE_DYNAMIC_CAPACITY_RELEASE_OPCODE 0x5605
#define DYNAMIC_CAPACITY_ADD_REFERENCE_OPCODE 0x5606
#define DYNAMIC_CAPACITY_REMOVE_REFERENCE_OPCODE 0x5607
#define DYNAMIC_CAPACITY_LIST_TAGS_OPCODE 0x5608


#define REGION_FLAG_NONVOLATILE                (1 << 2)
#define REGION_FLAG_SHARABLE                   (1 << 3)
#define REGION_FLAG_HW_MANAGED_COHERENCY       (1 << 4)
#define REGION_FLAG_INTERCONNECT_DYNAMIC_CAP   (1 << 5)
#define REGION_FLAG_READ_ONLY                  (1 << 6)

#define REGION_FLAG_SANITIZE_ON_RELEASE       (1 << 0)

#define SELECTION_POLICY_FREE                0x0
#define SELECTION_POLICY_CONTIGUOUS          0x1
#define SELECTION_POLICY_PRESCRIPTIVE        0x2
#define SELECTION_POLICY_ENABLE_SHARED_ACCESS 0x3

#define REMOVAL_POLICY_TAG_BASED              0x0
#define REMOVAL_POLICY_PRESCRIPTIVE           0x1
#define FLAG_FORCED_REMOVAL                   (1 << 4)
#define FLAG_SANITIZE_ON_RELEASE              (1 << 5)

typedef struct {
    uint64_t region_base;               // 00h 8: Region Base
    uint64_t region_decode_length;      // 08h 8: Region Decode Length
    uint64_t region_length;             // 10h 8: Region Length
    uint64_t region_block_size;         // 18h 8: Region Block Size
    uint8_t region_flags;               // 20h 1: Region Flags
    uint8_t reserved1[3];               // 21h 3: Reserved
    uint8_t sanitize_on_release;        // 24h 1: Sanitize on Release
    uint8_t reserved2[3];               // 25h 3: Reserved
} dc_region_config_entry;

typedef struct {
    uint64_t starting_dpa;            // 00h 08h: Starting DPA
    uint64_t length;                  // 08h 08h: Length
    uint64_t tag;                     // 10h 08h: Tag
    uint16_t shared_extent_sequence;  // 18h 02h: Shared Extent Sequence
    uint8_t reserved[6];              // 1Ah 06h: Reserved
} dynamic_capacity_extent;

typedef struct {
    uint64_t tag;                      // 00h 10h: Tag
    uint8_t flags;                     // 10h 1: Flags
    uint8_t reserved[3];               // 11h 3: Reserved
    uint8_t reference_bitmap[32];      // 14h 20h: Reference Bitmap
    uint8_t pending_reference_bitmap[32]; // 34h 20h: Pending Reference Bitmap
} dynamic_capacity_tag_info;

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

typedef struct {
    uint16_t host_id;               // 0h 2: Host ID
    uint8_t region_count;           // 2h 1: Region Count
    uint8_t starting_region_index;  // 3h 1: Starting Region Index
} get_host_dc_region_config_request_payload;

typedef struct {
    uint16_t host_id;                      // 0h 2: Host ID
    uint8_t num_available_regions;         // 2h 1: Number of Available Regions
    uint8_t num_regions_returned;          // 3h 1: Number of Regions Returned
    dc_region_config_entry region_config_list[]; // 4h Varies: Region Configuration List
    uint32_t total_num_supported_extents;  // Varies 4: Total Number of Supported Extents
    uint32_t num_available_extents;        // Varies 4: Number of Available Extents
    uint32_t total_num_supported_tags;     // Varies 4: Total Number of Supported Tags
    uint32_t num_available_tags;           // Varies 4: Number of Available Tags
} get_host_dc_region_config_response_payload;

typedef struct {
    uint8_t region_id;               // 0h 1: Region ID
    uint8_t reserved1[3];            // 1h 3: Reserved
    uint64_t region_block_size;      // 4h 8: Region Block Size
    uint8_t sanitize_on_release;     // Ch 1: Sanitize on Release and Reserved bits
    uint8_t reserved2[3];            // Dh 3: Reserved
} set_dc_region_config_request_payload;

typedef struct {
    uint16_t host_id;               // 0h 2: Host ID
    uint16_t reserved;              // 2h 2: Reserved
    uint32_t extent_count;          // 4h 4: Extent Count
    uint32_t starting_extent_index; // 8h 4: Starting Extent Index
} get_dc_region_extent_lists_request_payload;

typedef struct {
    uint16_t host_id;                 // 0h 2: Host ID
    uint16_t reserved1;               // 2h 2: Reserved
    uint32_t starting_extent_index;   // 4h 4: Starting Extent Index
    uint32_t returned_extent_count;   // 8h 4: Returned Extent Count
    uint32_t total_extent_count;      // Ch 4: Total Extent Count
    uint32_t extent_list_gen_num;     // 10h 4: Extent List Generation Number
    uint32_t reserved2;               // 14h 4: Reserved
    dynamic_capacity_extent extent_list[]; // 18h Varies: Extent List
} get_dc_region_extent_lists_response_payload;

typedef struct {
    uint16_t host_id;               // 00h 2: Host ID
    uint8_t selection_policy;       // 02h 1: Selection Policy (Bits[3:0]) and Reserved (Bits[7:4])
    uint8_t region_number;          // 03h 1: Region Number
    uint64_t length;                // 04h 8: Length
    uint64_t tag;                   // 0Ch 10h: Tag
    uint32_t extent_count;          // 1Ch 4: Extent Count
    dynamic_capacity_extent extent_list[]; // 20h Varies: Extent List (only when Selection Policy is Prescriptive)
} initiate_dynamic_capacity_add_request_payload;

typedef struct {
    uint16_t host_id;               // 00h 2: Host ID
    uint8_t flags;                  // 02h 1: Flags (Bits[3:0]: Removal Policy, Bit[4]: Forced Removal, Bit[5]: Sanitize on Release, Bits[7:6]: Reserved)
    uint8_t reserved1;              // 03h 1: Reserved
    uint64_t length;                // 04h 8: Length
    uint64_t tag;                   // 0Ch 10h: Tag
    uint32_t extent_count;          // 1Ch 4: Extent Count
    dynamic_capacity_extent extent_list[]; // 20h Varies: Extent List (only when Removal Policy is Prescriptive)
} initiate_dynamic_capacity_release_request_payload;

typedef struct {
    uint64_t tag;  // 00h 10h: Tag that is associated with the memory capacity to be preserved
} dynamic_capacity_add_reference_request_payload;

typedef struct {
    uint64_t tag;  // 00h 10h: Tag that is associated with the memory capacity
} dynamic_capacity_remove_reference_request_payload;

typedef struct {
    uint32_t starting_index;  // 00h 04h: Starting Index
    uint32_t max_tags;        // 04h 04h: Max Tags
} dynamic_capacity_list_tags_request_payload;

typedef struct {
    uint32_t generation_number;        // 00h 4: Generation Number
    uint32_t total_number_of_tags;     // 04h 4: Total Number of Tags
    uint32_t number_of_tags_returned;  // 08h 4: Number of Tags Returned
    uint8_t validity_bitmap;           // 0Ch 1: Validity Bitmap
    uint8_t reserved[3];               // 0Dh 3: Reserved
    dynamic_capacity_tag_info tags_list[]; // 10h Varies: Tags List (array of Dynamic Capacity Tag Information structures)
} dynamic_capacity_list_tags_response_payload;

// Function declarations
void get_dcd_info(uint64_t mailbox_base_address);
void get_host_dc_region_config(uint64_t mailbox_base_address, uint16_t host_id, uint8_t region_count, uint8_t starting_region_index);
void set_dc_region_config(uint64_t mailbox_base_address, uint8_t region_id, uint64_t region_block_size, uint8_t sanitize_on_release);
void get_dc_region_extent_lists(uint64_t mailbox_base_address, uint16_t host_id, uint32_t extent_count, uint32_t starting_extent_index);
void initiate_dynamic_capacity_add(uint64_t mailbox_base_address, uint16_t host_id, uint8_t selection_policy, uint8_t region_number, uint64_t length, uint64_t tag, uint32_t extent_count, dynamic_capacity_extent *extent_list);
void initiate_dynamic_capacity_release(uint64_t mailbox_base_address, uint16_t host_id, uint8_t flags, uint64_t length, uint64_t tag, uint32_t extent_count, dynamic_capacity_extent *extent_list);
void dynamic_capacity_add_reference(uint64_t mailbox_base_address, uint64_t tag);
void dynamic_capacity_remove_reference(uint64_t mailbox_base_address, uint64_t tag);
void dynamic_capacity_list_tags(uint64_t mailbox_base_address, uint32_t starting_index, uint32_t max_tags);

#endif // DCD_MANAGEMENT_H  