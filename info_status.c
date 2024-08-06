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

    int ret = send_mailbox_command_with_output_payload(mailbox_base_address, command);
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

    int ret = send_mailbox_command_with_output_payload(mailbox_base_address, command);
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

     int ret = send_mailbox_command_with_output_payload(mailbox_base_address, command);
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