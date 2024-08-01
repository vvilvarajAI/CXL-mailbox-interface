#ifndef INFO_STATUS_H
#define INFO_STATUS_H
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
