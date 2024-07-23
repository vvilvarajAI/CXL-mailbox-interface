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

get_dcd_info(uint64_t mailbox_base_address)
{
    uint32_t *payload = (uint32_t *)malloc(sizeof(dcd_info_response_payload));
    uint16_t payload_size = sizeof(dcd_info_response_payload);
    memset(payload, 0, payload_size);
    uint16_t ret_code =0;

    int ret = send_mailbox_command(mailbox_base_address, GET_DCD_INFO_OPCODE, &payload_size, payload, &ret_code); 
    printf("\t\tDCD Info Response Payload:\n");
    printf("\t\tNumber of Hosts: %d\n", ((dcd_info_response_payload *)payload)->num_host);
    printf("\t\tNumber of Supported DC Regions: %d\n", ((dcd_info_response_payload *)payload)->num_supported_dc_regions);
    printf("\t\tCapacity Selection Policy: %d\n", ((dcd_info_response_payload *)payload)->capacity_selection_policy);
    printf("\t\tCapacity Removal Policy: %d\n", ((dcd_info_response_payload *)payload)->capacity_removal_policy);
    printf("\t\tSanitize on Release Config Support Mask: %d\n", ((dcd_info_response_payload *)payload)->sanitize_on_release_config_support_mask);
    printf("\t\tTotal Dynamic Capacity: %ld\n", ((dcd_info_response_payload *)payload)->total_dyn_cap);
    printf("\t\tRegion 0 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_0_supported_block_size_mask);
    printf("\t\tRegion 1 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_1_supported_block_size_mask);
    printf("\t\tRegion 2 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_2_supported_block_size_mask);
    printf("\t\tRegion 3 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_3_supported_block_size_mask);
    printf("\t\tRegion 4 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_4_supported_block_size_mask);
    printf("\t\tRegion 5 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_5_supported_block_size_mask);
    printf("\t\tRegion 6 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_6_supported_block_size_mask);
    printf("\t\tRegion 7 Supported Block Size Mask: %ld\n", ((dcd_info_response_payload *)payload)->reg_7_supported_block_size_mask);

    print_ret_code(ret_code);
    free(payload);
}

void get_host_dc_region_config(uint64_t mailbox_base_address, uint16_t host_id, uint8_t region_count, uint8_t starting_region_index) {
    // Allocate memory for the request payload
    get_host_dc_region_config_request_payload request_payload = {
        .host_id = host_id,
        .region_count = region_count,
        .starting_region_index = starting_region_index
    };

    // Calculate the size of the response payload
    uint16_t response_payload_size = sizeof(get_host_dc_region_config_response_part1_t) + sizeof(get_host_dc_region_config_response_part2_t) + region_count * sizeof(dc_region_config_entry);
    
    // Allocate memory for the response payload
    uint32_t *response_payload = (uint32_t *)malloc(response_payload_size);
    memset(response_payload, 0, response_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, GET_HOST_DC_REGION_CONFIG_OPCODE, &response_payload_size, response_payload, &ret_code);

    // Print the response payload
    get_host_dc_region_config_response_part1_t *payload = (get_host_dc_region_config_response_part1_t *)response_payload;
    printf("\t\tHost DC Region Config Response Payload:\n");
    printf("\t\tHost ID: %d\n", payload->host_id);
    printf("\t\tNumber of Available Regions: %d\n", payload->num_available_regions);
    printf("\t\tNumber of Regions Returned: %d\n", payload->num_regions_returned);

    for (uint8_t i = 0; i < region_count; i++) {
        dc_region_config_entry *entry = &payload->region_config_list[i];
        printf("\t\tRegion %d:\n", i);
        printf("\t\t\tRegion Base: %lu\n", entry->region_base);
        printf("\t\t\tRegion Decode Length: %lu\n", entry->region_decode_length);
        printf("\t\t\tRegion Length: %lu\n", entry->region_length);
        printf("\t\t\tRegion Block Size: %lu\n", entry->region_block_size);
        printf("\t\t\tRegion Flags: %d\n", entry->region_flags);
        printf("\t\t\tSanitize on Release: %d\n", entry->sanitize_on_release);
    }

    get_host_dc_region_config_response_part2_t *payload2 = (get_host_dc_region_config_response_part2_t *)(response_payload + sizeof(get_host_dc_region_config_response_part1_t)+ region_count * sizeof(dc_region_config_entry));
    printf("\t\tTotal Number of Supported Extents: %u\n", payload2->total_num_supported_extents);
    printf("\t\tNumber of Available Extents: %u\n", payload2->num_available_extents);
    printf("\t\tTotal Number of Supported Tags: %u\n", payload2->total_num_supported_tags);
    printf("\t\tNumber of Available Tags: %u\n", payload2->num_available_tags);

    print_ret_code(ret_code);

    // Free the allocated memory
    free(response_payload);
}

void set_dc_region_config(uint64_t mailbox_base_address, uint8_t region_id, uint64_t region_block_size, uint8_t sanitize_on_release) {
    // Allocate memory for the request payload
    set_dc_region_config_request_payload request_payload = {
        .region_id = region_id,
        .region_block_size = region_block_size,
        .sanitize_on_release = sanitize_on_release
    };

    // Calculate the size of the request payload
    uint16_t request_payload_size = sizeof(set_dc_region_config_request_payload);

    // Allocate memory for the response payload (assuming no specific response structure)
    uint32_t *response_payload = (uint32_t *)malloc(request_payload_size);
    memset(response_payload, 0, request_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, SET_DC_REGION_CONFIG_OPCODE, &request_payload_size, response_payload, &ret_code);

    // Print the response payload (if any)
    printf("\t\tSet DC Region Config Response Payload:\n");
    printf("\t\tRegion ID: %d\n", request_payload.region_id);
    printf("\t\tRegion Block Size: %lu\n", request_payload.region_block_size);
    printf("\t\tSanitize on Release: %d\n", request_payload.sanitize_on_release);

    print_ret_code(ret_code);

    // Free the allocated memory
    free(response_payload);
}

void get_dc_region_extent_lists(uint64_t mailbox_base_address, uint16_t host_id, uint32_t extent_count, uint32_t starting_extent_index) {
    // Allocate memory for the request payload
    get_dc_region_extent_lists_request_payload request_payload = {
        .host_id = host_id,
        .extent_count = extent_count,
        .starting_extent_index = starting_extent_index
    };

    // Calculate the size of the response payload
    uint16_t response_payload_size = sizeof(get_dc_region_extent_lists_response_payload) + extent_count * sizeof(dynamic_capacity_extent);

    // Allocate memory for the response payload
    uint32_t *response_payload = (uint32_t *)malloc(response_payload_size);
    memset(response_payload, 0, response_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, GET_DC_REGION_EXTENT_LISTS_OPCODE, &response_payload_size, response_payload, &ret_code);

    // Print the response payload
    get_dc_region_extent_lists_response_payload *payload = (get_dc_region_extent_lists_response_payload *)response_payload;
    printf("\t\tDC Region Extent Lists Response Payload:\n");
    printf("\t\tHost ID: %d\n", payload->host_id);
    printf("\t\tStarting Extent Index: %u\n", payload->starting_extent_index);
    printf("\t\tReturned Extent Count: %u\n", payload->returned_extent_count);
    printf("\t\tTotal Extent Count: %u\n", payload->total_extent_count);
    printf("\t\tExtent List Generation Number: %u\n", payload->extent_list_gen_num);

    for (uint32_t i = 0; i < payload->returned_extent_count; i++) {
        dynamic_capacity_extent *extent = &payload->extent_list[i];
        printf("\t\tExtent %d:\n", i);
        printf("\t\t\tStarting DPA: %lu\n", extent->starting_dpa);
        printf("\t\t\tLength: %lu\n", extent->length);
        printf("\t\t\tTag: %lu\n", extent->tag);
        printf("\t\t\tShared Extent Sequence: %u\n", extent->shared_extent_sequence);
    }

    print_ret_code(ret_code);

    // Free the allocated memory
    free(response_payload);
}
void initiate_dynamic_capacity_add(uint64_t mailbox_base_address, uint16_t host_id, uint8_t selection_policy, uint8_t region_number, uint64_t length, uint64_t tag, uint32_t extent_count, dynamic_capacity_extent *extent_list) {
    // Calculate the size of the request payload
    uint16_t request_payload_size = sizeof(initiate_dynamic_capacity_add_request_payload) + extent_count * sizeof(dynamic_capacity_extent);

    // Allocate memory for the request payload
    initiate_dynamic_capacity_add_request_payload *request_payload = (initiate_dynamic_capacity_add_request_payload *)malloc(request_payload_size);
    request_payload->host_id = host_id;
    request_payload->selection_policy = selection_policy;
    request_payload->region_number = region_number;
    request_payload->length = length;
    request_payload->tag = tag;
    request_payload->extent_count = extent_count;

    // Copy the extent list to the request payload
    memcpy(request_payload->extent_list, extent_list, extent_count * sizeof(dynamic_capacity_extent));

    // Allocate memory for the response payload (assuming no specific response structure)
    uint32_t *response_payload = (uint32_t *)malloc(request_payload_size);
    memset(response_payload, 0, request_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, INITIATE_DYNAMIC_CAPACITY_ADD_OPCODE, &request_payload_size, response_payload, &ret_code);

    // Print the response payload (if any)
    printf("\t\tInitiate Dynamic Capacity Add Response Payload:\n");
    printf("\t\tHost ID: %d\n", request_payload->host_id);
    printf("\t\tSelection Policy: %d\n", request_payload->selection_policy);
    printf("\t\tRegion Number: %d\n", request_payload->region_number);
    printf("\t\tLength: %lu\n", request_payload->length);
    printf("\t\tTag: %lu\n", request_payload->tag);
    printf("\t\tExtent Count: %u\n", request_payload->extent_count);

    for (uint32_t i = 0; i < request_payload->extent_count; i++) {
        dynamic_capacity_extent *extent = &request_payload->extent_list[i];
        printf("\t\tExtent %d:\n", i);
        printf("\t\t\tStarting DPA: %lu\n", extent->starting_dpa);
        printf("\t\t\tLength: %lu\n", extent->length);
        printf("\t\t\tTag: %lu\n", extent->tag);
        printf("\t\t\tShared Extent Sequence: %u\n", extent->shared_extent_sequence);
    }

    print_ret_code(ret_code);

    // Free the allocated memory
    free(request_payload);
    free(response_payload);
}

void initiate_dynamic_capacity_release(uint64_t mailbox_base_address, uint16_t host_id, uint8_t flags, uint64_t length, uint64_t tag, uint32_t extent_count, dynamic_capacity_extent *extent_list) {
    // Calculate the size of the request payload
    uint16_t request_payload_size = sizeof(initiate_dynamic_capacity_release_request_payload) + extent_count * sizeof(dynamic_capacity_extent);

    // Allocate memory for the request payload
    initiate_dynamic_capacity_release_request_payload *request_payload = (initiate_dynamic_capacity_release_request_payload *)malloc(request_payload_size);
    request_payload->host_id = host_id;
    request_payload->flags = flags;
    request_payload->length = length;
    request_payload->tag = tag;
    request_payload->extent_count = extent_count;

    // Copy the extent list to the request payload
    memcpy(request_payload->extent_list, extent_list, extent_count * sizeof(dynamic_capacity_extent));

    // Allocate memory for the response payload (assuming no specific response structure)
    uint32_t *response_payload = (uint32_t *)malloc(request_payload_size);
    memset(response_payload, 0, request_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, INITIATE_DYNAMIC_CAPACITY_RELEASE_OPCODE, &request_payload_size, response_payload, &ret_code);

    // Print the response payload (if any)
    printf("\t\tInitiate Dynamic Capacity Release Response Payload:\n");
    printf("\t\tHost ID: %d\n", request_payload->host_id);
    printf("\t\tFlags: %d\n", request_payload->flags);
    printf("\t\tLength: %lu\n", request_payload->length);
    printf("\t\tTag: %lu\n", request_payload->tag);
    printf("\t\tExtent Count: %u\n", request_payload->extent_count);

    for (uint32_t i = 0; i < request_payload->extent_count; i++) {
        dynamic_capacity_extent *extent = &request_payload->extent_list[i];
        printf("\t\tExtent %d:\n", i);
        printf("\t\t\tStarting DPA: %lu\n", extent->starting_dpa);
        printf("\t\t\tLength: %lu\n", extent->length);
        printf("\t\t\tTag: %lu\n", extent->tag);
        printf("\t\t\tShared Extent Sequence: %u\n", extent->shared_extent_sequence);
    }

    print_ret_code(ret_code);

    // Free the allocated memory
    free(request_payload);
    free(response_payload);
}

void dynamic_capacity_add_reference(uint64_t mailbox_base_address, uint64_t tag) {
    // Allocate memory for the request payload
    dynamic_capacity_add_reference_request_payload request_payload = {
        .tag = tag
    };

    // Calculate the size of the request payload
    uint16_t request_payload_size = sizeof(dynamic_capacity_add_reference_request_payload);

    // Allocate memory for the response payload (assuming no specific response structure)
    uint32_t *response_payload = (uint32_t *)malloc(request_payload_size);
    memset(response_payload, 0, request_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, DYNAMIC_CAPACITY_ADD_REFERENCE_OPCODE, &request_payload_size, response_payload, &ret_code);

    // Print the response payload (if any)
    printf("\t\tDynamic Capacity Add Reference Response Payload:\n");
    printf("\t\tTag: %lu\n", request_payload.tag);

    print_ret_code(ret_code);

    // Free the allocated memory
    free(response_payload);
}

void dynamic_capacity_remove_reference(uint64_t mailbox_base_address, uint64_t tag) {
    // Allocate memory for the request payload
    dynamic_capacity_remove_reference_request_payload request_payload = {
        .tag = tag
    };

    // Calculate the size of the request payload
    uint16_t request_payload_size = sizeof(dynamic_capacity_remove_reference_request_payload);

    // Allocate memory for the response payload (assuming no specific response structure)
    uint32_t *response_payload = (uint32_t *)malloc(request_payload_size);
    memset(response_payload, 0, request_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, DYNAMIC_CAPACITY_REMOVE_REFERENCE_OPCODE, &request_payload_size, response_payload, &ret_code);

    // Print the response payload (if any)
    printf("\t\tDynamic Capacity Remove Reference Response Payload:\n");
    printf("\t\tTag: %lu\n", request_payload.tag);

    print_ret_code(ret_code);

    // Free the allocated memory
    free(response_payload);
}

void dynamic_capacity_list_tags (uint64_t mailbox_base_address, uint32_t starting_index, uint32_t max_tags)
{
    // Allocate memory for the request payload
    dynamic_capacity_list_tags_request_payload request_payload = {
        .starting_index = starting_index,
        .max_tags = max_tags
    };

    // Calculate the size of the response payload
    uint16_t response_payload_size = sizeof(dynamic_capacity_list_tags_response_payload);

    // Allocate memory for the response payload
    dynamic_capacity_list_tags_response_payload *response_payload = (dynamic_capacity_list_tags_response_payload *)malloc(response_payload_size);
    memset(response_payload, 0, response_payload_size);

    uint16_t ret_code = 0;

    // Send the mailbox command
    int ret = send_mailbox_command(mailbox_base_address, DYNAMIC_CAPACITY_LIST_TAGS_OPCODE, &response_payload_size, response_payload, &ret_code);

    // Print the response payload
    printf("\t\tDynamic Capacity List Tags Response Payload:\n");
    printf("\t\tGeneration Number: %u\n", response_payload->generation_number);
    printf("\t\tTotal Number of Tags: %u\n", response_payload->total_number_of_tags);
    printf("\t\tNumber of Tags Returned: %u\n", response_payload->number_of_tags_returned);
    printf("\t\tValidity Bitmap: %u\n", response_payload->validity_bitmap);

    // Print the tags list
    for (uint32_t i = 0; i < response_payload->number_of_tags_returned; i++) {
        dynamic_capacity_tag_info *tag_info = &response_payload->tags_list[i];
        printf("\t\tTag %u:\n", i);
        // Print the tag information
    }

    print_ret_code(ret_code);

    // Free the allocated memory
    free(response_payload);
}