#pragma once

typedef struct PCIE_CLASS_CODE {
    uint8_t Prog_if;
    uint8_t Sub_Class_Code;  
    uint8_t Base_Class_Code; 
} PCIE_CLASS_CODE;

typedef struct BAR {
    uint32_t Region_Type    : 1;
    uint32_t Locatable      : 2;
    uint32_t Prefetchable   : 1;
    uint32_t Base_Address   : 28;
} BAR;

typedef struct PCIE_CONFIG_HDR {
    uint16_t Vendor_ID;
    uint16_t Device_ID;
    uint16_t Command;
    int16_t Status;
    uint8_t Rev_ID;
    PCIE_CLASS_CODE Class_Code;
    uint32_t Misc;
    BAR Base_Address_Registers[6];
    int32_t Misc2[6];
} PCIE_CONFIG_HDR; 

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

typedef struct {
    uint8_t Register_BIR : 3;
    uint8_t RsvdP : 5;
    uint8_t Register_Block_Identifier : 8;
    uint16_t Register_Block_Offset_Low : 16;
} REGISTER_OFFSET_LOW;

typedef struct {
    uint32_t Register_Block_Offset_High;
} REGISTER_OFFSET_HIGH;

typedef struct {
    REGISTER_OFFSET_LOW Register_Offset_Low;
    REGISTER_OFFSET_HIGH Register_Offset_High;
} REGISTER_BLOCK;

typedef struct {
    PCIE_EXT_CAP_HDR PCIE_ext_cap_hdr;
    uint16_t RsvdP;
    REGISTER_BLOCK Register_Block[4];
} registerLocator;

typedef struct DEVICE_CAPABILITIES_ARRAY_REGISTER {
    uint16_t Capability_ID;
    uint8_t Version;
    uint8_t Reserved;
    uint16_t Capabilities_Count;
    uint8_t Reserved2[10];
} DEVICE_CAPABILITIES_ARRAY_REGISTER;

typedef struct {
    uint16_t Capability_ID;
    uint8_t Version;
    uint8_t Reserved;
    uint32_t Offset;
    uint32_t Length;
    uint32_t Reserved2;
} DEVICE_CAPABILITIES_HEADER;

typedef struct {
    DEVICE_CAPABILITIES_ARRAY_REGISTER Device_Capabilities_Array_Register; 
    DEVICE_CAPABILITIES_HEADER Device_Capability_Header[3]; // Replace MAX_HEADERS with desired header count
    uint8_t Device_Capability[4096-16-16*3];  // Replace MAX_DEVICE_CAPABILITY_SIZE
} MemoryDeviceRegisters;


void print_config_header(struct pci_dev *pdev);
void print_extended_config(struct pci_dev *pdev);
uint16_t get_dvsec_register_locator_offset(struct pci_dev *pdev);
uint32_t get_mailbox_base_address (struct pci_dev *pdev);
uint32_t get_register_block_number_from_header(registerLocator *register_locator);