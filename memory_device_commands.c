#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pci/pci.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "cxl_mailbox.h"
#include "dcd_management.h"
#include "memory_device_commands.h"



void identify_memory_device(uint64_t mailbox_base_address) {
    uint32_t *payload = (uint32_t *)malloc(sizeof(identify_memory_device_response_payload));
    uint16_t payload_size = sizeof(identify_memory_device_response_payload);
    memset(payload, 0, payload_size);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, IDENTIFY_MEMORY_DEVICE_OPCODE, &payload_size, payload, &ret_code);
    printf("Identify Memory Device Response Payload:\n");
    // Print relevant fields from payload
    print_ret_code(ret_code);
    free(payload);
}

void get_memory_device_status(uint64_t mailbox_base_address) {
    uint32_t *payload = (uint32_t *)malloc(sizeof(memory_device_status_response_payload));
    uint16_t payload_size = sizeof(memory_device_status_response_payload);
    memset(payload, 0, payload_size);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, GET_MEMORY_DEVICE_STATUS_OPCODE, &payload_size, payload, &ret_code);
    printf("Memory Device Status Response Payload:\n");
    // Print relevant fields from payload
    print_ret_code(ret_code);
    free(payload);
}

void get_memory_health_info(uint64_t mailbox_base_address) {
    uint32_t *payload = (uint32_t *)malloc(sizeof(memory_health_info_response_payload));
    uint16_t payload_size = sizeof(memory_health_info_response_payload);
    memset(payload, 0, payload_size);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, GET_MEMORY_HEALTH_INFO_OPCODE, &payload_size, payload, &ret_code);
    printf("Memory Health Info Response Payload:\n");
    // Print relevant fields from payload
    print_ret_code(ret_code);
    free(payload);
}

void get_supported_features(uint64_t mailbox_base_address) {
    uint32_t *payload = (uint32_t *)malloc(sizeof(supported_features_response_payload));
    uint16_t payload_size = sizeof(supported_features_response_payload);
    memset(payload, 0, payload_size);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, GET_SUPPORTED_FEATURES_OPCODE, &payload_size, payload, &ret_code);
    printf("Supported Features Response Payload:\n");
    // Print relevant fields from payload
    print_ret_code(ret_code);
    free(payload);
}

void get_memory_configuration(uint64_t mailbox_base_address) {
    uint32_t *payload = (uint32_t *)malloc(sizeof(memory_configuration_response_payload));
    uint16_t payload_size = sizeof(memory_configuration_response_payload);
    memset(payload, 0, payload_size);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, GET_MEMORY_CONFIGURATION_OPCODE, &payload_size, payload, &ret_code);
    printf("Memory Configuration Response Payload:\n");
    // Print relevant fields from payload
    print_ret_code(ret_code);
    free(payload);
}

void set_memory_configuration(uint64_t mailbox_base_address, const memory_configuration_request_payload *config) {
    uint16_t payload_size = sizeof(memory_configuration_request_payload);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, SET_MEMORY_CONFIGURATION_OPCODE, &payload_size, (uint32_t *)config, &ret_code);
    printf("Set Memory Configuration Response:\n");
    print_ret_code(ret_code);
}

void get_memory_device_logs(uint64_t mailbox_base_address) {
    uint32_t *payload = (uint32_t *)malloc(sizeof(memory_device_logs_response_payload));
    uint16_t payload_size = sizeof(memory_device_logs_response_payload);
    memset(payload, 0, payload_size);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, GET_MEMORY_DEVICE_LOGS_OPCODE, &payload_size, payload, &ret_code);
    printf("Memory Device Logs Response Payload:\n");
    // Print relevant fields from payload
    print_ret_code(ret_code);
    free(payload);
}

void firmware_update(uint64_t mailbox_base_address, const firmware_update_request_payload *fw_update) {
    uint16_t payload_size = sizeof(firmware_update_request_payload);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, FIRMWARE_UPDATE_OPCODE, &payload_size, (uint32_t *)fw_update, &ret_code);
    printf("Firmware Update Response:\n");
    print_ret_code(ret_code);
}
