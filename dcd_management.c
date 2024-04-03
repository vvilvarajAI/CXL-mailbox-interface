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
