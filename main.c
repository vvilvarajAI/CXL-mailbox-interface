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
#include "main.h"

#define CXL_Vendor_ID 0x1E98
#define CXL_DEVICE_REGISTERS_ID 0x03

#define CXL_TIMESTAMP_SIZE 0x8 // expressed in bytes

unsigned int debug_mode = 0;

int main(int argc, char *argv[])
{
    if (argc != 4 || strcmp(argv[2], "-d") != 0)
    {
        printf("Usage: %s <BDF> -d <debug_mode>\n", argv[0]);
        return 1;
    }
    
    debug_mode = atoi(argv[3]);
    if (debug_mode == 1)
    {
        printf("Debug mode enabled\n");
    }
    else
    {
        printf("Debug mode disabled\n");
    }

    const char *bdf = argv[1];
    int domain, bus, dev, func;
    if (sscanf(bdf, "%x:%x:%x.%x", &domain, &bus, &dev, &func) != 4)
    {
        printf("Invalid BDF format: %s\n", bdf);
        return 1;
    }
    struct pci_access *pacc;
    struct pci_dev *pdev;

    pacc = pci_alloc();
    pci_init(pacc);
    printf("Initializing PCI library...\n");
    pacc->method = PCI_ACCESS_ECAM;
    pacc->debugging = 1;
    pacc->debug = printf;
    pci_scan_bus(pacc);

    printf("Scanning PCI bus...\n");
    printf("Domain: %04x\n", domain);
    printf("Bus: %02x\n", bus);
    printf("Device: %02x\n", dev);
    printf("Function: %02x\n", func);

    for (pdev = pacc->devices; pdev; pdev = pdev->next)
    {
        pci_fill_info(pdev, PCI_FILL_IDENT | PCI_FILL_BASES | PCI_FILL_CLASS | PCI_FILL_LABEL);

        if (pdev->domain == domain && pdev->bus == bus && pdev->dev == dev && pdev->func == func)
        {
            printf("Found device %s\n", pdev->label);
            break;
        }

        /* Access more detailed information if needed (e.g., BARs) */
    }
    printf("Device: Vendor 0x%04x, Device 0x%04x\n", pdev->vendor_id, pdev->device_id);
    printf("Device Class: 0x%04x\n", pdev->device_class);
    print_config_header(pdev);
#ifdef DEBUG
    print_extended_config(pdev);
#endif
    uint16_t register_locator_offset = get_dvsec_register_locator_offset(pdev);
    printf("register Locator header Offset: 0x%04x\n", register_locator_offset);

    uint64_t mailbox_base_address = get_mailbox_base_address(pdev);
    printf("Mailbox Base Address: 0x%llx\n", mailbox_base_address);

    cci_commands(mailbox_base_address);
    pci_cleanup(pacc);
    return 0;
}

void cci_commands(uint64_t mailbox_base_address)
{
    uint16_t host_id = 1;
    uint8_t region_count = 2;
    uint8_t starting_region_index = 0;
    uint8_t region_id = 1;
    uint64_t region_block_size = 4096;
    uint8_t sanitize_on_release = 1;
    uint32_t extent_count = 2;
    uint32_t starting_extent_index = 0;
    uint8_t selection_policy = 0;
    uint8_t region_number = 0;
    uint64_t length = 1024;
    uint64_t tag = 12345;
    uint8_t flags = 0;
    uint32_t max_tags = 10;
    dynamic_capacity_extent extent_list[2] = {
        {.starting_dpa = 0x2000, .length = 512, .tag = 111, .shared_extent_sequence = 0},
        {.starting_dpa = 0x3000, .length = 512, .tag = 222, .shared_extent_sequence = 1}};

    int choice;

    while (1) {
        printf("\nSelect a function to call:\n");
        printf("1. cxl_mailbox_clear_timestamp\n");
        printf("2. cxl_mailbox_get_timestamp\n");
        printf("3. get_dcd_info\n");
        printf("4. get_host_dc_region_config\n");
        printf("5. set_dc_region_config\n");
        printf("6. get_dc_region_extent_lists\n");
        printf("7. initiate_dynamic_capacity_add\n");
        printf("8. initiate_dynamic_capacity_release\n");
        printf("9. dynamic_capacity_add_reference\n");
        printf("10. dynamic_capacity_remove_reference\n");
        printf("11. dynamic_capacity_list_tags\n");
        printf("12. Exit\n");
        printf("Enter your choice: ");
        scanf("%d", &choice);

        switch (choice) {
            case 1:
                cxl_mailbox_clear_timestamp(mailbox_base_address);
                break;
            case 2:
                cxl_mailbox_get_timestamp(mailbox_base_address);
                break;
            case 3:
                get_dcd_info(mailbox_base_address);
                break;
            case 4:
                get_host_dc_region_config(mailbox_base_address, host_id, region_count, starting_region_index);
                break;
            case 5:
                set_dc_region_config(mailbox_base_address, region_id, region_block_size, sanitize_on_release);
                break;
            case 6:
                get_dc_region_extent_lists(mailbox_base_address, host_id, extent_count, starting_extent_index);
                break;
            case 7:
                initiate_dynamic_capacity_add(mailbox_base_address, host_id, selection_policy, region_number, length, tag, extent_count, extent_list);
                break;
            case 8:
                initiate_dynamic_capacity_release(mailbox_base_address, host_id, flags, length, tag, extent_count, extent_list);
                break;
            case 9:
                dynamic_capacity_add_reference(mailbox_base_address, tag);
                break;
            case 10:
                dynamic_capacity_remove_reference(mailbox_base_address, tag);
                break;
            case 11:
                dynamic_capacity_list_tags(mailbox_base_address, starting_extent_index, max_tags);
                break;
            case 12:
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
}
