#ifndef INFO_STATUS_H
#define INFO_STATUS_H
#pragma once
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include<stdlib.h>
#include "cxl_mailbox.h"

#define IDENTIFY_OPCODE 0x0001
#define BACKGROUND_OPERATION_STATUS_OPCODE 0x0002
#define GET_RESPONSE_MESSAGE_LIMIT_OPCODE 0x0003
#define SET_RESPONSE_MESSAGE_LIMIT_OPCODE 0x0004
#define REQUEST_ABORT_BACKGROUND_OPERATION_OPCODE 0x0005

#define GET_SUPPORTED_LOGS_OPCODE 0x0400

// Enum for UUID types
typedef enum {
    UUID_COMMAND_EFFECTS_LOG,
    UUID_VENDOR_DEBUG_LOG,
    UUID_COMPONENT_STATE_DUMP_LOG,
    UUID_DDR5_ERROR_CHECK_SCRUB_LOG,
    UUID_MEDIA_TEST_CAPABILITY_LOG,
    UUID_MEDIA_TEST_RESULTS_SHORT_LOG,
    UUID_MEDIA_TEST_RESULTS_LONG_LOG,
    UUID_TYPE_COUNT  // This will give the number of UUID types
} uuid_type_t;

extern const uint8_t uuid_array[UUID_TYPE_COUNT][16];

// Define the UUID structure
typedef struct {
    uint8_t uuid[16];
} uuid_t;

// Define the structure for Get Supported Logs Supported Log Entry
typedef struct {
    uuid_t log_identifier;  // UUID representing the log
    uint32_t log_size;      // Maximum number of bytes of log data
} supported_log_entry_t;

// Define the structure for Get Supported Logs Output Payload
typedef struct {
    uint16_t number_of_supported_log_entries;  // Number of Supported Log Entries
    uint8_t reserved[6];                       // Reserved
    supported_log_entry_t *supported_log_entries;  // Pointer to the array of supported log entries
} get_supported_logs_output_payload_t;


typedef struct {
    uint16_t pcie_vendor_id;            // 00h 2: PCIe Vendor ID
    uint16_t pcie_device_id;            // 02h 2: PCIe Device ID
    uint16_t pcie_subsystem_vendor_id;  // 04h 2: PCIe Subsystem Vendor ID
    uint16_t pcie_subsystem_id;         // 06h 2: PCIe Subsystem ID
    uint64_t device_serial_number;      // 08h 8: Device Serial Number
    uint8_t max_supported_message_size; // 10h 1: Maximum Supported Message Size
    uint8_t component_type;             // 11h 1: Component Type
} identify_output_payload_t;

typedef struct {
    uint8_t background_operation_status; // 00h 1: Background Operation Status
    uint8_t reserved;                    // 01h 1: Reserved
    uint16_t command_opcode;             // 02h 2: Command Opcode
    uint16_t return_code;                // 04h 2: Return Code
    uint16_t vendor_specific_extended_status; // 06h 2: Vendor Specific Extended Status
} background_operation_status_output_payload_t;

typedef struct {
    uint8_t response_message_limit; // 00h 1: Response Message Limit
} get_response_message_limit_output_payload_t;

typedef struct {
    uint8_t response_message_limit; // 00h 1: Response Message Limit
} set_response_message_limit_input_payload_t;

typedef struct {
    uint8_t response_message_limit; // 00h 1: Response Message Limit
} set_response_message_limit_output_payload_t;


void identify_device(uint64_t mailbox_base_address);
void get_background_operation_status(uint64_t mailbox_base_address);
void get_response_message_limit(uint64_t mailbox_base_address);
void set_response_message_limit(uint64_t mailbox_base_address, uint8_t response_message_limit);
void request_abort_background_operation(uint64_t mailbox_base_address);

#endif // INFO_STATUS_H
