#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pci/pci.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "cxl_mailbox.h"

#define CXL_Vendor_ID 0x1E98
#define CXL_DEVICE_REGISTERS_ID 0x03

#define CXL_TIMESTAMP_SIZE 0x8 // expressed in bytes

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        printf("Usage: %s <BDF>\n", argv[0]);
        return 1;
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

    uint32_t mailbox_base_address = get_mailbox_base_address(pdev);
    printf("Mailbox Base Address: 0x%08x\n", mailbox_base_address);

    cxl_mailbox_clear_timestamp(mailbox_base_address);
    cxl_mailbox_get_timestamp(mailbox_base_address);
    pci_cleanup(pacc);
    return 0;
}
