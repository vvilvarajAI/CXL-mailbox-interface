#include <stdio.h>
#include <stdlib.h>
#include <pci/pci.h>
#include "main.h"

#define CXL_Vendor_ID 0x1E98

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
#ifdef DEBUG
    print_extended_config(pdev);
#endif

    uint32_t ext_cap_off = 0x100;
    uint16_t ext_cap_off_val=0;
    uint16_t val = pci_read_word(pdev,ext_cap_off+0x02);
    printf("val: 0x%04x\n", val);
    ext_cap_off_val = val>>4;
    printf("ext_cap_off_val: 0x%04x\n", ext_cap_off_val);

    PCIE_EXT_CAP_HDR pcie_ext_cap_hdr;
    pci_read_block(pdev, ext_cap_off_val, &pcie_ext_cap_hdr, sizeof(pcie_ext_cap_hdr));
    printf("PCIE_EXT_CAP_HDR: PCIE_ext_cap_ID: 0x%04x, Cap_Ver: 0x%04x, Next_Cap_ofs: 0x%04x\n", pcie_ext_cap_hdr.PCIE_ext_cap_ID, pcie_ext_cap_hdr.Cap_Ver, pcie_ext_cap_hdr.Next_Cap_ofs);
    printf("DVSEC_HDR1: DVSEC_Vendor_ID: 0x%04x, DVSEC_Rev: 0x%04x, DVSEC_Length: 0x%04x\n", pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Vendor_ID, pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Rev, pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Length);
    printf("DVSEC_HDR2: DVSEC_ID: 0x%04x\n", pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID);
    if (pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Vendor_ID == CXL_Vendor_ID) {
                #ifdef DEBUG
                printf("DVSEC ID is %x\n", pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID);
                #endif
                if (pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID == 0x8) {
                    printf("CXL Device found\n");
                }
            }
    pci_cleanup(pacc);
    return 0;
}
void print_extended_config(struct pci_dev *pdev)
{
    // Print the configuration space
    printf("Configuration Space:\n");
    unsigned char config_space[4096];
    pci_read_block(pdev, 0, config_space, sizeof(config_space));
    for (int i = 0; i < sizeof(config_space); i++)
    {
        printf("%02X ", config_space[i]);
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
}