#ifndef EVENTS_H
#define EVENTS_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pci/pci.h>
#include "cxl_mailbox.h"

#define GET_EVENT_RECORDS_OPCODE 0x0100
#define CLEAR_EVENT_RECORDS_OPCODE 0x0101
#define GET_EVENT_INTERRUPT_POLICY_OPCODE 0x0102
#define SET_EVENT_INTERRUPT_POLICY_OPCODE 0x0103
#define GET_MCTP_EVENT_INTERRUPT_POLICY_OPCODE 0x0104
#define SET_MCTP_EVENT_INTERRUPT_POLICY_OPCODE 0x0105
#define EVENT_NOTIFICATION_OPCODE 0x0106
#define GFD_ENHANCED_EVENT_NOTIFICATION_OPCODE 0x0107
#define GFD_TO_GAE_ENHANCED_EVENT_NOTIFICATION_OPCODE 0x0108
#define GET_GAM_BUFFER_OPCODE 0x0109
#define SET_GAM_BUFFER_OPCODE 0x010A

#define UUID_GENERAL_MEDIA_EVENT_RECORD       {0xfb, 0xcd, 0x0a, 0x77, 0xc2, 0x60, 0x41, 0x7f, 0x85, 0xa9, 0x08, 0x8b, 0x16, 0x21, 0xeb, 0xa6}
#define UUID_DRAM_EVENT_RECORD                {0x60, 0x1d, 0xcb, 0xb3, 0x9c, 0x06, 0x4e, 0xab, 0xb8, 0xaf, 0x4e, 0x9b, 0xfb, 0x5c, 0x96, 0x24}
#define UUID_MEMORY_MODULE_EVENT_RECORD       {0xfe, 0x92, 0x74, 0x75, 0xdd, 0x59, 0x43, 0x39, 0xa5, 0x86, 0x79, 0xba, 0xb1, 0x13, 0xb7, 0x74}
#define UUID_MEMORY_SPARING_EVENT_RECORD      {0xe7, 0x1f, 0x3a, 0x40, 0x2d, 0x29, 0x40, 0x92, 0x8a, 0x39, 0x4d, 0x1c, 0x96, 0x6c, 0x7c, 0x65}
#define UUID_PHYSICAL_SWITCH_EVENT_RECORD     {0x77, 0xcf, 0x92, 0x71, 0x9c, 0x02, 0x47, 0x0b, 0x9f, 0xe4, 0xbc, 0x7b, 0x75, 0xf2, 0xda, 0x97}
#define UUID_VIRTUAL_SWITCH_EVENT_RECORD      {0x40, 0xd2, 0x64, 0x25, 0x33, 0x96, 0x4c, 0x4d, 0xa5, 0xda, 0x3d, 0x47, 0x26, 0x3a, 0xf4, 0x25}
#define UUID_MLD_PORT_EVENT_RECORD            {0x8d, 0xc4, 0x43, 0x63, 0x0c, 0x96, 0x47, 0x10, 0xb7, 0xbf, 0x04, 0xbb, 0x99, 0x53, 0x4c, 0x3f}
#define UUID_DYNAMIC_CAPACITY_EVENT_RECORD    {0xca, 0x95, 0xaf, 0xa7, 0xf1, 0x83, 0x40, 0x18, 0x8c, 0x2f, 0x95, 0x26, 0x8e, 0x10, 0x1a, 0x2a}

typedef struct {
    uint8_t event_record_identifier[16];   // 00h 10h: Event Record Identifier (UUID)
    uint8_t event_record_length;           // 10h 1: Event Record Length
    struct {
        uint8_t severity:2;                // Bits[1:0]: Event Record Severity
        uint8_t permanent_condition:1;     // Bit[2]: Permanent Condition
        uint8_t maintenance_needed:1;      // Bit[3]: Maintenance Needed
        uint8_t performance_degraded:1;    // Bit[4]: Performance Degraded
        uint8_t hardware_replacement_needed:1; // Bit[5]: Hardware Replacement Needed
        uint8_t maintenance_operation_subclass_valid_flag:1; // Bit[6]: Maintenance Operation Subclass Valid Flag
        uint8_t reserved1:1;               // Bit[7]: Reserved
        uint16_t reserved2;                // Bits[23:8]: Reserved
    } event_record_flags;                  // 11h 3: Event Record Flags
    uint16_t event_record_handle;          // 14h 2: Event Record Handle
    uint16_t related_event_record_handle;  // 16h 2: Related Event Record Handle
    uint64_t event_record_timestamp;       // 18h 8: Event Record Timestamp
    uint8_t maintenance_operation_class;   // 20h 1: Maintenance Operation Class
    uint8_t maintenance_operation_subclass; // 21h 1: Maintenance Operation Subclass
    uint8_t reserved[14];                  // 22h 0Eh: Reserved
    uint8_t event_record_data[80];         // 30h 50h: Event Record Data (format depends on the Event Record Identifier)
} common_event_record_format_t;

typedef struct {
    uint8_t id_validity_flags;             // 00h 1: ID Validity Flags
    union {
        struct {
            uint8_t reserved[14];          // Bytes[14:0] are reserved
        } reserved_format;
        struct {
            uint8_t pldm_entity_identification[6]; // Bytes[5:0] = PLDM Entity Identification Information
            uint8_t reserved[9];           // Bytes[14:6] are reserved
        } entity_id_format;
        struct {
            uint8_t reserved1[6];          // Bytes[5:0] are reserved
            uint8_t resource_id[4];        // Bytes[9:6] = Resource ID
            uint8_t reserved2[5];          // Bytes[14:10] are reserved
        } resource_id_format;
        struct {
            uint8_t pldm_entity_identification[6]; // Bytes[5:0] = PLDM Entity Identification Information
            uint8_t resource_id[4];        // Bytes[9:6] = Resource ID
            uint8_t reserved[5];           // Bytes[14:10] are reserved
        } full_format;
    };
} component_identifier_format_t;

typedef struct {
    uint8_t common_event_record[48];       // 00h 30h: Common Event Record
    uint64_t physical_address;             // 30h 8: Physical Address
    struct {
        uint8_t uncorrectable_event:1;     // Bit[0]: Uncorrectable Event
        uint8_t threshold_event:1;         // Bit[1]: Threshold Event
        uint8_t poison_list_overflow_event:1; // Bit[2]: Poison List Overflow Event
        uint8_t reserved:5;                // Bits[7:3]: Reserved
    } memory_event_descriptor;             // 38h 1: Memory Event Descriptor
    uint8_t memory_event_type;             // 39h 1: Memory Event Type
    uint8_t transaction_type;              // 3Ah 1: Transaction Type
    struct {
        uint16_t channel_valid:1;          // Bit[0]: Channel field valid
        uint16_t rank_valid:1;             // Bit[1]: Rank field valid
        uint16_t device_field_valid:1;     // Bit[2]: Device field valid
        uint16_t component_identifier_valid:1; // Bit[3]: Component Identifier field valid
        uint16_t component_identifier_format:1; // Bit[4]: Component Identifier format
        uint16_t reserved:11;              // Bits[15:5]: Reserved
    } validity_flags;                      // 3Bh 2: Validity Flags
    uint8_t channel;                       // 3Dh 1: Channel
    uint8_t rank;                          // 3Eh 1: Rank
    uint8_t device;                        // 3Fh 1: Device
    uint8_t reserved1[3];                  // 40h 3: Reserved
    uint8_t component_identifier[16];      // 42h 10h: Component Identifier
    struct {
        uint8_t detected_errors_multiple_components:1; // Bit[0]: Detected errors in multiple memory components
        uint8_t programmable_threshold_exceeded:1; // Bit[1]: Programmable threshold exceeded
        uint8_t reserved:6;                // Bits[7:2]: Reserved
    } advanced_corrected_memory_error_threshold_event_flags; // 52h 1: Advanced Programmable Corrected Memory Error Threshold Event Flags
    uint8_t corrected_memory_error_count_at_event[3]; // 53h 3: Corrected Memory Error Count at Event
    uint8_t memory_event_subtype;          // 56h 1: Memory Event Sub-Type
    uint8_t reserved2[41];                 // 57h 29h: Reserved
} general_media_event_record_t;


typedef struct {
    uint8_t common_event_record[48];       // 00h 30h: Common Event Record
    uint64_t physical_address;             // 30h 8: Physical Address
    struct {
        uint8_t uncorrectable_event:1;     // Bit[0]: Uncorrectable Event
        uint8_t threshold_event:1;         // Bit[1]: Threshold Event
        uint8_t poison_list_overflow_event:1; // Bit[2]: Poison List Overflow Event
        uint8_t reserved:5;                // Bits[7:3]: Reserved
    } memory_event_descriptor;             // 38h 1: Memory Event Descriptor
    uint8_t memory_event_type;             // 39h 1: Memory Event Type
    uint8_t transaction_type;              // 3Ah 1: Transaction Type
    struct {
        uint16_t channel_valid:1;          // Bit[0]: Channel field valid
        uint16_t rank_valid:1;             // Bit[1]: Rank field valid
        uint16_t nibble_mask_valid:1;      // Bit[2]: Nibble Mask field valid
        uint16_t bank_group_valid:1;       // Bit[3]: Bank Group field valid
        uint16_t bank_valid:1;             // Bit[4]: Bank field valid
        uint16_t row_valid:1;              // Bit[5]: Row field valid
        uint16_t column_valid:1;           // Bit[6]: Column field valid
        uint16_t correction_mask_valid:1;  // Bit[7]: Correction Mask field valid
        uint16_t component_identifier_valid:1; // Bit[8]: Component Identifier field valid
        uint16_t component_identifier_format:1; // Bit[9]: Component Identifier format
        uint16_t sub_channel_valid:1;      // Bit[10]: Sub-channel field valid
        uint16_t reserved:5;               // Bits[15:11]: Reserved
    } validity_flags;                      // 3Bh 2: Validity Flags
    uint8_t channel;                       // 3Dh 1: Channel
    uint8_t rank;                          // 3Eh 1: Rank
    uint8_t nibble_mask[3];                // 3Fh 3: Nibble Mask
    uint8_t bank_group;                    // 42h 1: Bank Group
    uint8_t bank;                          // 43h 1: Bank
    uint8_t row[3];                        // 44h 3: Row
    uint8_t column[2];                     // 47h 2: Column
    uint8_t correction_mask[4][8];         // 49h 32: Correction Masks (4 sets of 8 bytes each)
    uint8_t component_identifier[16];      // 69h 10h: Component Identifier
    uint8_t sub_channel;                   // 79h 1: Sub-channel
    struct {
        uint8_t multiple_memory_components:1; // Bit[0]: Detected errors in multiple memory components
        uint8_t programmable_threshold_exceeded:1; // Bit[1]: Programmable threshold exceeded
        uint8_t reserved:6;                // Bits[7:2]: Reserved
    } corrected_memory_error_threshold_event_flags; // 7Ah 1: Advanced Programmable Corrected Memory Error Threshold Event Flags
    uint8_t cvme_count_at_event[3];        // 7Bh 3: CVME Count at Event
    uint8_t memory_event_subtype;          // 7Eh 1: Memory Event Sub-Type
    uint8_t reserved2;                     // 7Fh 1: Reserved
} dram_event_record_t;

typedef struct {
    uint8_t common_event_record[48];       // 00h 30h: Common Event Record
    uint8_t device_event_type;             // 30h 1: Device Event Type
    uint8_t device_health_information[18]; // 31h 12h: Device Health Information
    struct {
        uint16_t component_identifier_valid:1; // Bit[0]: Component Identifier field valid
        uint16_t component_identifier_format:1; // Bit[1]: Component Identifier format
        uint16_t reserved:14;              // Bits[15:2]: Reserved
    } validity_flags;                      // 43h 2: Validity Flags
    uint8_t component_identifier[16];      // 45h 10h: Component Identifier
    uint8_t device_event_subtype;          // 55h 1: Device Event Sub-Type
    uint8_t reserved[42];                  // 56h 2Ah: Reserved
} memory_module_event_record_t;


typedef struct {
    uint8_t common_event_record[48];       // 00h 30h: Common Event Record
    uint8_t maintenance_operation_class;   // 30h 1: Maintenance Operation Class
    uint8_t maintenance_operation_subclass; // 31h 1: Maintenance Operation Subclass
    struct {
        uint8_t query_resources_flag:1;    // Bit[0]: Query Resources Flag
        uint8_t hard_sparing_flag:1;       // Bit[1]: Hard Sparing Flag
        uint8_t device_initiated:1;        // Bit[2]: Device Initiated
        uint8_t reserved:5;                // Bits[7:3]: Reserved
    } flags;                               // 32h 1: Flags
    uint8_t result;                        // 33h 1: Result
    struct {
        uint16_t channel_valid:1;          // Bit[0]: Channel field valid
        uint16_t rank_valid:1;             // Bit[1]: Rank field valid
        uint16_t nibble_mask_valid:1;      // Bit[2]: Nibble Mask field valid
        uint16_t bank_group_valid:1;       // Bit[3]: Bank Group field valid
        uint16_t bank_valid:1;             // Bit[4]: Bank field valid
        uint16_t row_valid:1;              // Bit[5]: Row field valid
        uint16_t column_valid:1;           // Bit[6]: Column field valid
        uint16_t component_identifier_valid:1; // Bit[7]: Component Identifier field valid
        uint16_t component_identifier_format:1; // Bit[8]: Component Identifier format
        uint16_t sub_channel_valid:1;      // Bit[9]: Sub-channel field valid
        uint16_t reserved:6;               // Bits[15:10]: Reserved
    } validity_flags;                      // 34h 2: Validity Flags
    uint8_t reserved1[6];                  // 36h 6: Reserved
    uint16_t spare_resource_available;     // 3Ch 2: Spare Resource Available
    uint8_t channel;                       // 3Eh 1: Channel
    uint8_t rank;                          // 3Fh 1: Rank
    uint8_t nibble_mask[3];                // 40h 3: Nibble Mask
    uint8_t bank_group;                    // 43h 1: Bank Group
    uint8_t bank;                          // 44h 1: Bank
    uint8_t row[3];                        // 45h 3: Row
    uint8_t column[2];                     // 48h 2: Column
    uint8_t component_identifier[16];      // 4Ah 10h: Component Identifier
    uint8_t sub_channel;                   // 5Ah 1: Sub-Channel
    uint8_t reserved2[37];                 // 5Bh 25h: Reserved
} memory_sparing_event_record_t;

typedef struct {
    uint8_t common_event_record[48];   // 00h 30h: Common Event Record
    uint8_t vendor_specific_event_data[80]; // 30h 50h: Vendor Specific Event Data
} vendor_specific_event_record_t;

typedef struct {
    uint8_t common_event_record[48];           // 00h 30h: Common Event Record
    uint8_t dynamic_capacity_event_type;       // 30h 1: Dynamic Capacity Event Type
    struct {
        uint8_t available_tags_valid:1;        // Bit[0]: Number of Available Tags field valid
        uint8_t reserved:7;                    // Bits[7:1]: Reserved
    } validity_flags;                          // 31h 1: Validity Flags
    uint16_t host_id;                          // 32h 2: Host ID
    uint8_t updated_region_index;              // 34h 1: Updated Region Index
    struct {
        uint8_t more:1;                        // Bit[0]: More flag
        uint8_t reserved:7;                    // Bits[7:1]: Reserved
    } flags;                                   // 35h 1: Flags
    uint16_t reserved1;                        // 36h 2: Reserved
    uint8_t dynamic_capacity_extent[40];       // 38h 28h: Dynamic Capacity Extent
    uint8_t reserved2[24];                     // 60h 18h: Reserved
    uint32_t number_of_available_extents;      // 78h 4: Number of Available Extents
    uint32_t number_of_available_tags;         // 7Ch 4: Number of Available Tags
} dynamic_capacity_event_record_t;

typedef struct {
    uint8_t event_log; // 00h 1: Event Log
    // 00h = Informational Event Log
    // 01h = Warning Event Log
    // 02h = Failure Event Log
    // 03h = Fatal Event Log
    // 04h = Dynamic Capacity Event Log
    // All other encodings are reserved
} get_event_records_input_payload_t;

typedef struct {
    struct {
        uint8_t overflow:1;                // Bit[0]: Overflow
        uint8_t more_event_records:1;      // Bit[1]: More Event Records
        uint8_t reserved:6;                // Bits[7:2]: Reserved
    } flags;                               // 00h 1: Flags
    uint8_t reserved1;                     // 01h 1: Reserved
    uint16_t overflow_error_count;         // 02h 2: Overflow Error Count
    uint64_t first_overflow_event_timestamp; // 04h 8: First Overflow Event Timestamp
    uint64_t last_overflow_event_timestamp; // 0Ch 8: Last Overflow Event Timestamp
    uint16_t event_record_count;           // 14h 2: Event Record Count
    uint8_t reserved2[6];                  // 16h 0Ah: Reserved
    // Assuming the size of the Event Records list varies, it can be represented as a flexible array member
    uint8_t event_records[];               // 20h Varies: Event Records
} get_event_records_output_payload_t;

typedef struct {
    uint8_t event_log; // 00h 1: Event Log
    // 00h = Informational Event Log
    // 01h = Warning Event Log
    // 02h = Failure Event Log
    // 03h = Fatal Event Log
    // 04h = Dynamic Capacity Event Log
    // All other encodings are reserved
    struct {
        uint8_t clear_all_events:1;        // Bit[0]: Clear All Events
        uint8_t reserved:7;                // Bits[7:1]: Reserved
    } clear_event_flags;                   // 01h 1: Clear Event Flags
    uint8_t number_of_event_record_handles; // 02h 1: Number of Event Record Handles
    uint8_t reserved[3];                   // 03h 3: Reserved
    uint64_t event_record_handles[];       // 06h Varies: Event Record Handles
} clear_event_records_input_payload_t;

typedef struct {
    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t interrupt_message_number:4; // Bits[7:4]: Interrupt Message Number
    } informational_event_log_interrupt_settings; // 00h 1: Informational Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t interrupt_message_number:4; // Bits[7:4]: Interrupt Message Number
    } warning_event_log_interrupt_settings; // 01h 1: Warning Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t interrupt_message_number:4; // Bits[7:4]: Interrupt Message Number
    } failure_event_log_interrupt_settings; // 02h 1: Failure Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t interrupt_message_number:4; // Bits[7:4]: Interrupt Message Number
    } fatal_event_log_interrupt_settings;   // 03h 1: Fatal Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t interrupt_message_number:4; // Bits[7:4]: Interrupt Message Number
    } dynamic_capacity_event_log_interrupt_settings; // 04h 1: Dynamic Capacity Event Log Interrupt Settings

} get_event_interrupt_policy_output_payload_t;

typedef struct {
    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t fw_interrupt_message_number:4; // Bits[7:4]: FW Interrupt Message Number
    } informational_event_log_interrupt_settings; // 00h 1: Informational Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t fw_interrupt_message_number:4; // Bits[7:4]: FW Interrupt Message Number
    } warning_event_log_interrupt_settings; // 01h 1: Warning Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t fw_interrupt_message_number:4; // Bits[7:4]: FW Interrupt Message Number
    } failure_event_log_interrupt_settings; // 02h 1: Failure Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t fw_interrupt_message_number:4; // Bits[7:4]: FW Interrupt Message Number
    } fatal_event_log_interrupt_settings;   // 03h 1: Fatal Event Log Interrupt Settings

    struct {
        uint8_t interrupt_mode:2;           // Bits[1:0]: Interrupt Mode
        uint8_t reserved1:2;                // Bits[3:2]: Reserved
        uint8_t fw_interrupt_message_number:4; // Bits[7:4]: FW Interrupt Message Number
    } dynamic_capacity_event_log_interrupt_settings; // 04h 1: Dynamic Capacity Event Log Interrupt Settings

} set_event_interrupt_policy_input_payload_t;

typedef struct {
    struct {
        uint16_t new_uncleared_informational_event_log:1; // Bit[0]
        uint16_t new_uncleared_warning_event_log:1;       // Bit[1]
        uint16_t new_uncleared_failure_event_log:1;       // Bit[2]
        uint16_t new_uncleared_fatal_event_log:1;         // Bit[3]
        uint16_t new_uncleared_dynamic_capacity_event_log:1; // Bit[4]
        uint16_t reserved:10;                             // Bits[14:5]
        uint16_t background_operation_completed:1;        // Bit[15]
    } event_interrupt_settings;                            // 00h 2: Event Interrupt Settings
} mctp_event_interrupt_policy_t;

typedef struct {
    struct {
        uint16_t informational_event_log:1;           // Bit[0]: Informational Event Log has uncleared record(s)
        uint16_t warning_event_log:1;                 // Bit[1]: Warning Event Log has uncleared record(s)
        uint16_t failure_event_log:1;                 // Bit[2]: Failure Event Log has uncleared record(s)
        uint16_t fatal_event_log:1;                   // Bit[3]: Fatal Event Log has uncleared record(s)
        uint16_t dynamic_capacity_event_log:1;        // Bit[4]: Dynamic Capacity Event Log has uncleared record(s)
        uint16_t reserved:10;                         // Bits[14:5]: Reserved
        uint16_t background_operation_completed:1;    // Bit[15]: Background Operation completed
    } event;                                           // 00h 2: Event
} event_notification_input_payload_t;

typedef enum {
    NO_OP = 0x00,                    // No-Op
    STANDARD_EVENT_NOTIFICATION = 0x01,  // Standard Event Notification
    GFD_ACCESS_ERROR = 0x02,         // GFD Access Error
    GFD_UNRECOGNIZED_REQUEST = 0x03, // GFD Unrecognized Request
    GFD_UNEXPECTED_PACKET = 0x04,    // GFD Unexpected Packet
    GFD_INVALID_INPUT = 0x05,        // GFD Invalid Input
    GFD_PERSISTENT_FLUSH_FAILURE = 0x06, // GFD Persistent Flush Failure
    GFD_EXECUTION_FAILURE_NON_FATAL = 0x07, // GFD Execution Failure: Non-Fatal
    GFD_EXECUTION_FAILURE_FATAL = 0x08, // GFD Execution Failure: Fatal
    GFD_HEALTH_ALERTS = 0x09,        // GFD Health Alerts
    GFD_EXTENT_LIST_CHANGE = 0x0A    // GFD Extent List Change
} gfd_notification_type_t;

typedef struct {
    union {
        struct {
            uint8_t reserved_0:8;
        } no_op;

        struct {
            uint8_t reserved_0:8;
        } standard_event_notification;

        struct {
            uint8_t hpa_to_dpa_mapping_non_existent:1;
            uint8_t dpa_to_hpa_snoop_mapping_failed:1;
            uint8_t dpa_to_memory_group_id_failed:1;
            uint8_t spid_access_permission_denied:1;
            uint8_t reserved_4_7:4;
        } gfd_access_error;

        struct {
            uint8_t not_a_valid_memory_request_opcode:1;
            uint8_t not_a_supported_request_type:1;
            uint8_t reserved_2_7:6;
        } gfd_unrecognized_request;

        struct {
            uint8_t reserved_0:8;
        } gfd_unexpected_packet;

        struct {
            uint8_t reserved_0:8;
        } gfd_invalid_input;

        struct {
            uint8_t dirty_shutdown_counter_incremented:1;
            uint8_t internal_error_detected_during_flush:1;
            uint8_t media_error_detected_during_flush:1;
            uint8_t reserved_3_7:5;
        } gfd_persistent_flush_failure;

        struct {
            uint8_t dpa_to_hpa_snoop_mapping_failed:1;
            uint8_t back_invalidate_request_unsuccessful:1;
            uint8_t back_invalidate_request_no_response:1;
            uint8_t transient_internal_uncorrectable_ecc_error_detected:1;
            uint8_t reserved_4_7:4;
        } gfd_execution_failure_non_fatal;

        struct {
            uint8_t persistent_internal_uncorrectable_ecc_error_detected:1;
            uint8_t persistent_media_access_error:1;
            uint8_t reserved_2_7:6;
        } gfd_execution_failure_fatal;

        struct {
            uint8_t life_used_programmable_warning_threshold_tripped:1;
            uint8_t device_over_temperature_programmable_warning_threshold_tripped:1;
            uint8_t device_under_temperature_programmable_warning_threshold_tripped:1;
            uint8_t corrected_volatile_memory_error_programmable_warning_threshold_tripped:1;
            uint8_t corrected_persistent_memory_error_programmable_warning_threshold_tripped:1;
            uint8_t reserved_5_7:3;
        } gfd_health_alerts;
    } trigger_values;
} gfd_notification_type_trigger_values_t;

typedef struct {
    uint16_t pbr_id;                             // 00h 2: PBR_ID
    struct {
        uint16_t informational_event_log:1;      // Bit[0]: Informational Event Log has uncleared record(s)
        uint16_t warning_event_log:1;            // Bit[1]: Warning Event Log has uncleared record(s)
        uint16_t failure_event_log:1;            // Bit[2]: Failure Event Log has uncleared record(s)
        uint16_t fatal_event_log:1;              // Bit[3]: Fatal Event Log has uncleared record(s)
        uint16_t dynamic_capacity_event_log:1;   // Bit[4]: Dynamic Capacity Event Log has uncleared record(s)
        uint16_t reserved:10;                    // Bits[14:5]: Reserved
        uint16_t background_operation_completed:1; // Bit[15]: Background Operation completed
    } event;                                      // 02h 2: Event

    gfd_notification_type_t notification_type;    // 04h 1: GFD Notification Type
    gfd_notification_type_trigger_values_t trigger_values; // 05h 1: Notification Type Trigger

    uint16_t rpid;                                // 06h 2: RPID
    uint64_t dpa;                                 // 08h 8: DPA
    uint64_t hpa;                                 // 10h 8: HPA
    uint16_t memory_group_id;                     // 18h 2: Memory Group ID (GrpID)
    uint8_t memory_req_opcode;                    // 1Ah 1: Memory Req Opcode
    uint8_t reserved_1;                           // 1Bh 1: Reserved

    struct {
        uint16_t reserved_0:1;                    // Bit[0]: Reserved
        uint16_t request_associated:1;            // Bit[1]: Request Associated
        uint16_t dpa_valid:1;                     // Bit[2]: DPA Valid
        uint16_t hpa_valid:1;                     // Bit[3]: HPA Valid
        uint16_t memory_group_id_valid:1;         // Bit[4]: Memory Group ID Valid
        uint16_t memory_req_opcode_valid:1;       // Bit[5]: Memory Req Opcode Valid
        uint16_t reserved_6_15:10;                // Bits[15:6]: Reserved
    } flags;                                       // 1Ch 2: Flags

    uint16_t event_record_handle;                 // 1Eh 2: Event Record Handle
    uint64_t timestamp;                           // 20h 8: Timestamp
} enhanced_event_notification_input_payload_t;

// Get GAM Buffer Response Payload Structure
typedef struct {
    uint64_t valid:1;                   // Bit[0]: Valid
    uint64_t buffer_overflow:1;         // Bit[1]: Buffer Overflow
    uint64_t reserved_2_4:3;            // Bits[4:2]: Reserved
    uint64_t gam_buffer_address:47;     // Bits[51:5]: GAM Buffer Address
    uint64_t reserved_52_54:2;          // Bits[55:52]: Reserved
    uint64_t head_index:8;              // Bits[63:56]: Head Index
} get_gam_buffer_response_payload_t;

// Set GAM Buffer Address Request Payload Structure
typedef struct {
    uint64_t valid:1;                   // Bit[0]: Valid
    uint64_t clear_overflow:1;          // Bit[1]: Clear Overflow
    uint64_t reserved_2_4:3;            // Bits[4:2]: Reserved
    uint64_t gam_buffer_address:47;     // Bits[51:5]: GAM Buffer Address
    uint64_t reserved_52_54:2;          // Bits[55:52]: Reserved
    uint64_t tail_index:8;              // Bits[63:56]: Tail Index
} set_gam_buffer_address_request_payload_t;

#endif // EVENTS_H