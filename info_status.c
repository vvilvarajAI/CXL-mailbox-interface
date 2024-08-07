#include"info_status.h"
#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include "cxl_mailbox.h"

void identify_device(uint64_t mailbox_base_address)
{
    uint32_t *payload = (uint32_t *)malloc(sizeof(identify_output_payload_t));
    uint16_t payload_size = sizeof(identify_output_payload_t);
    memset(payload, 0, sizeof(identify_output_payload_t));
    uint16_t ret_code = 0;
    MailboxCommand *command = (MailboxCommand *)malloc(sizeof(MailboxCommand));
    command->command = IDENTIFY_OPCODE;
    command->input_payload_size = 0;
    command->input_payload = NULL;
    command->output_payload_size = payload_size;
    command->output_payload = payload;
    command->ret_code = &ret_code;

    int ret = cxl_cmd_libcxl(command->command, command->output_payload,command->output_payload_size);
    free(command);
    printf("\t\tIdentify Device\n");
    if (ret == 0)
    {
        identify_output_payload_t *identify_payload = (identify_output_payload_t *)payload;
        printf("\t\tPCIe Vendor ID: 0x%04x\n", identify_payload->pcie_vendor_id);
        printf("\t\tPCIe Device ID: 0x%04x\n", identify_payload->pcie_device_id);
        printf("\t\tPCIe Subsystem Vendor ID: 0x%04x\n", identify_payload->pcie_subsystem_vendor_id);
        printf("\t\tPCIe Subsystem ID: 0x%04x\n", identify_payload->pcie_subsystem_id);
        printf("\t\tDevice Serial Number: 0x%016lx\n", identify_payload->device_serial_number);
        printf("\t\tMaximum Supported Message Size: 0x%02x\n", identify_payload->max_supported_message_size);
        printf("\t\tComponent Type: 0x%02x\n", identify_payload->component_type);
    }
    else
    {
        printf("\t\tFailed to get Identify Device ret = %d \n",ret);
    }
    print_ret_code(ret_code);
    free(payload);
}

void get_background_operation_status(uint64_t mailbox_base_address)
{
    uint32_t *payload = (uint32_t *)malloc(sizeof(background_operation_status_output_payload_t));
    uint16_t payload_size = sizeof(background_operation_status_output_payload_t);
    memset(payload, 0, sizeof(background_operation_status_output_payload_t));
    uint16_t ret_code = 0;
    MailboxCommand *command = (MailboxCommand *)malloc(sizeof(MailboxCommand));
    command->command = BACKGROUND_OPERATION_STATUS_OPCODE;
    command->input_payload_size = 0;
    command->input_payload = NULL;
    command->output_payload_size = payload_size;
    command->output_payload = payload;
    command->ret_code = &ret_code;

    int ret = cxl_cmd_libcxl(command->command, command->output_payload,command->output_payload_size);
    printf("\t\tGet Background Operation Status\n");
    if (ret == 0)
    {
        background_operation_status_output_payload_t *background_operation_status_payload = (background_operation_status_output_payload_t *)command->output_payload;
        printf("\t\tBackground Operation Status: 0x%02x\n", background_operation_status_payload->background_operation_status);
        printf("\t\tCommand Opcode: 0x%04x\n", background_operation_status_payload->command_opcode);
        printf("\t\tReturn Code: 0x%04x\n", background_operation_status_payload->return_code);
        printf("\t\tVendor Specific Extended Status: 0x%04x\n", background_operation_status_payload->vendor_specific_extended_status);
    }
    else
    {
        printf("\t\tFailed to get Background Operation Status\n");
    }
    print_ret_code(ret_code);
    free(payload);
    
}
void get_response_message_limit(uint64_t mailbox_base_address)
{
    uint32_t *payload = (uint32_t *)malloc(sizeof(get_response_message_limit_output_payload_t));
    uint16_t payload_size = sizeof(get_response_message_limit_output_payload_t);
    memset(payload, 0, sizeof(get_response_message_limit_output_payload_t));
    uint16_t ret_code = 0;
    MailboxCommand *command = (MailboxCommand *)malloc(sizeof(MailboxCommand));
    command->command = GET_RESPONSE_MESSAGE_LIMIT_OPCODE;
    command->input_payload_size = 0;
    command->input_payload = NULL;
    command->output_payload_size = payload_size;
    command->output_payload = payload;
    command->ret_code = &ret_code;

    int ret = cxl_cmd_libcxl(command->command, command->output_payload,command->output_payload_size);
    printf("\t\tGet Response Message Limit\n");
    if (ret == 0)
    {
        get_response_message_limit_output_payload_t *get_response_message_limit_payload = (get_response_message_limit_output_payload_t *)command->output_payload;
        printf("\t\tResponse Message Limit: 0x%02x\n", get_response_message_limit_payload->response_message_limit);
    }
    else
    {
        printf("\t\tFailed to get Response Message Limit\n");
    }
    print_ret_code(ret_code);
    free(payload);
}

// Function to compare UUIDs
int compare_uuid(const uint8_t uuid1[16], const uint8_t uuid2[16]) {
    return memcmp(uuid1, uuid2, 16);
}

// Array of UUIDs corresponding to the enum values
const uint8_t uuid_array[UUID_TYPE_COUNT][16] = {
    [UUID_COMMAND_EFFECTS_LOG]      = {0x0d, 0xa9, 0xc0, 0xb5, 0xbf, 0x41, 0x4b, 0x78, 0x8f, 0x79, 0x96, 0xb1, 0x62, 0x3b, 0x3f, 0x17},
    [UUID_VENDOR_DEBUG_LOG]         = {0x5e, 0x18, 0x19, 0xd9, 0x11, 0xa9, 0x40, 0x0c, 0x81, 0x1f, 0xd6, 0x07, 0x19, 0x40, 0x3d, 0x86},
    [UUID_COMPONENT_STATE_DUMP_LOG] = {0xb3, 0xfa, 0xb4, 0xcf, 0x01, 0xb6, 0x43, 0x32, 0x94, 0x3e, 0x5e, 0x99, 0x62, 0xf2, 0x35, 0x67},
    [UUID_DDR5_ERROR_CHECK_SCRUB_LOG] = {0xf1, 0x72, 0x0d, 0x60, 0xa7, 0xa9, 0x43, 0x06, 0xa0, 0x03, 0x11, 0x94, 0x8f, 0x9e, 0x07, 0x7c},
    [UUID_MEDIA_TEST_CAPABILITY_LOG] = {0xe6, 0xdf, 0xa3, 0x2c, 0xd1, 0x3e, 0x4a, 0x5c, 0x8c, 0xa8, 0x99, 0xbe, 0xbb, 0xf7, 0x31, 0xa4},
    [UUID_MEDIA_TEST_RESULTS_SHORT_LOG] = {0x2c, 0x25, 0x55, 0x22, 0x8c, 0xe4, 0x11, 0xec, 0xb9, 0x09, 0x02, 0x42, 0xac, 0x12, 0x00, 0x02},
    [UUID_MEDIA_TEST_RESULTS_LONG_LOG] = {0xc1, 0xfe, 0x0b, 0x3e, 0x7a, 0x00, 0x44, 0x8e, 0xa2, 0x4e, 0xa6, 0xab, 0xbf, 0xe5, 0x87, 0xa}
};

// Function to find the matching UUID type
uuid_type_t find_matching_uuid_type(const supported_log_entry_t *log_entry) {
    for (uuid_type_t type = 0; type < UUID_TYPE_COUNT; type++) {
        if (compare_uuid(log_entry->log_identifier.uuid, uuid_array[type]) == 0) {
            return type;
        }
    }
    return UUID_TYPE_COUNT;  // Return an invalid type if no match is found
}

void get_supported_logs(uint64_t mailbox_base_address)
{
    uint32_t *payload = (uint32_t *)malloc(sizeof(get_supported_logs_output_payload_t));
    uint16_t payload_size = sizeof(get_supported_logs_output_payload_t);
    memset(payload, 0, sizeof(get_supported_logs_output_payload_t));
    uint16_t ret_code = 0;
    MailboxCommand *command = (MailboxCommand *)malloc(sizeof(MailboxCommand));
    command->command = GET_SUPPORTED_LOGS_OPCODE;
    command->input_payload_size = 0;
    command->input_payload = NULL;
    command->output_payload_size = payload_size;
    command->output_payload = payload;
    command->ret_code = &ret_code;

    int ret = cxl_cmd_libcxl(command->command, command->output_payload,command->output_payload_size);
    printf("\t\tGet Supported Logs\n");
    if (ret == 0)
    {
        get_supported_logs_output_payload_t *get_supported_logs_payload = (get_supported_logs_output_payload_t *)command->output_payload;
        printf("\t\tNumber of Supported Log Entries: 0x%04x\n", get_supported_logs_payload->number_of_supported_log_entries);

        uint16_t new_output_payload_size = sizeof(get_supported_logs_output_payload_t) + (get_supported_logs_payload->number_of_supported_log_entries * sizeof(supported_log_entry_t));
        (uint32_t *)realloc(command->output_payload, sizeof(get_supported_logs_output_payload_t) + (get_supported_logs_payload->number_of_supported_log_entries * sizeof(supported_log_entry_t)));
        printf("\t\t realloc done from %d to %d\n",command->output_payload_size, new_output_payload_size);
        command->output_payload_size = new_output_payload_size;
        ret = cxl_cmd_libcxl(command->command, command->output_payload,command->output_payload_size);
        if(ret != 0)
        {
            printf("\t\tFailed to get Supported Logs\n");
            print_ret_code(ret_code);
            free(payload);
            return;
        }
        get_supported_logs_payload = (get_supported_logs_output_payload_t *)command->output_payload;
        supported_log_entry_t supported_log_entry[get_supported_logs_payload->number_of_supported_log_entries];
        memcpy(supported_log_entry, get_supported_logs_payload->supported_log_entries, get_supported_logs_payload->number_of_supported_log_entries * sizeof(supported_log_entry_t));
        for (int i = 0; i < get_supported_logs_payload->number_of_supported_log_entries; i++)
        {
            printf("\t\tSupported Log Entry %d\n", i);
            printf("\t\t\tLog Identifier: ");
            for (int j = 0; j < 16; j++)
            {
                printf("%02x", supported_log_entry[i].log_identifier.uuid[j]);
            }
            printf("\n");
            printf("\t\t\tLog Size: 0x%08x\n", supported_log_entry[i].log_size);
        }
    }
    else
    {
        printf("\t\tFailed to get Supported Logs\n");
    }
    print_ret_code(ret_code);
    free(payload);
}
#if 0
void set_response_message_limit(uint64_t mailbox_base_address, uint8_t response_message_limit)
{
    uint32_t *payload = (uint32_t *)malloc(sizeof(set_response_message_limit_input_payload_t));
    uint16_t payload_size = sizeof(set_response_message_limit_input_payload_t);
    memset(payload, 0, sizeof(set_response_message_limit_input_payload_t));
    set_response_message_limit_input_payload_t *set_response_message_limit_payload = (set_response_message_limit_input_payload_t *)payload;
    set_response_message_limit_payload->response_message_limit = response_message_limit;
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, SET_RESPONSE_MESSAGE_LIMIT_OPCODE, &payload_size, payload, &ret_code);
    printf("\t\tSet Response Message Limit\n");
    if (ret == 0)
    {
        set_response_message_limit_output_payload_t *set_response_message_limit_output_payload = (set_response_message_limit_output_payload_t *)payload;
        printf("\t\tResponse Message Limit: 0x%02x\n", set_response_message_limit_output_payload->response_message_limit);
    }
    else
    {
        printf("\t\tFailed to set Response Message Limit\n");
    }
    print_ret_code(ret_code);
    free(payload);
}

void request_abort_background_operation(uint64_t mailbox_base_address)
{
    uint32_t *payload = (uint32_t *)malloc(sizeof(uint32_t));
    uint16_t payload_size = sizeof(uint32_t);
    memset(payload, 0, sizeof(uint32_t));
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, REQUEST_ABORT_BACKGROUND_OPERATION_OPCODE, &payload_size, payload, &ret_code);
    printf("\t\tRequest Abort Background Operation\n");
    if (ret == 0)
    {
        printf("\t\tRequest Abort Background Operation Success\n");
    }
    else
    {
        printf("\t\tFailed to Request Abort Background Operation\n");
    }
    print_ret_code(ret_code);
    free(payload);
}
#endif