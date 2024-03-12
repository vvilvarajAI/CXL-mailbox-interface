#pragma once
typedef struct {
    uint16_t DVSEC_Vendor_ID : 16;
    uint16_t DVSEC_Rev : 4;
    uint16_t DVSEC_Length : 12;
} DVSEC_HDR1;

typedef struct {
    uint16_t DVSEC_ID;
} DVSEC_HDR2;

typedef struct {
    uint16_t PCIE_ext_cap_ID : 16;
    uint16_t Cap_Ver : 4;
    uint16_t Next_Cap_ofs : 12;
    DVSEC_HDR1 DVSEC_hdr1;
    DVSEC_HDR2 DVSEC_hdr2;
} PCIE_EXT_CAP_HDR;


void print_extended_config(struct pci_dev *pdev);
