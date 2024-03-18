#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pci/pci.h>
#include <stdbool.h>
#include <string.h>
#include "main.h"
//#define DEBUG
#define CXL_Vendor_ID 0x1E98
#define CXL_DEVICE_REGISTERS_ID 0x03

void *my_memcpy(void *dest, const void *src, size_t n) {
    char *d = (char *)dest;
    const char *s = (char *)src;

    for (size_t i = 0; i < n; i++) {
        *d++ = *s++;
    }

    return dest;
}

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
    printf("Base Address 0: 0x%x\n", pdev->base_addr[0]);
    printf("Base Address 1: 0x%x\n", pdev->base_addr[1]);
    printf("Base Address 2: 0x%x\n", pdev->base_addr[2]);
    printf("Base Address 3: 0x%x\n", pdev->base_addr[3]);
    printf("Base Address 4: 0x%x\n", pdev->base_addr[4]);
    printf("Base Address 5: 0x%x\n", pdev->base_addr[5]);

    print_config_header(pdev);
#ifdef DEBUG
    print_extended_config(pdev);
#endif
    uint16_t register_locator_offset = get_dvsec_register_locator_offset(pdev);
    printf("%s:register Locator header Offset: 0x%04x\n", __func__,register_locator_offset);

    uint64_t mailbox_base_address = get_mailbox_base_address(pdev);
    printf("%s:Mailbox Base Address: 0x%llx\n",__func__, mailbox_base_address);

    int ret = send_mailbox_command(mailbox_base_address, 0x300); //0x300 is GET_TIMESTAMP command
    pci_cleanup(pacc);
    return 0;
}

void print_config_header(struct pci_dev *pdev)
{
    printf("Configuration Header:\n");
    PCIE_CONFIG_HDR pcie_config_hdr;
    pci_read_block(pdev, 0, &pcie_config_hdr, sizeof(pcie_config_hdr));
    for (int i = 0; i < sizeof(pcie_config_hdr); i++)
    {
        printf("%02X ", *((uint8_t*)&pcie_config_hdr + i));
        if ((i + 1) % 16 == 0)
        {
            printf("\n");
        }
    }
    printf("Vendor ID: 0x%04x\n", pcie_config_hdr.Vendor_ID);
    printf("Device ID: 0x%04x\n", pcie_config_hdr.Device_ID);
    printf("Command: 0x%04x\n", pcie_config_hdr.Command);
    printf("Status: 0x%04x\n", pcie_config_hdr.Status);
    printf("Rev ID: 0x%02x\n", pcie_config_hdr.Rev_ID);
    printf("Class Code: 0x%06x\n", pcie_config_hdr.Class_Code);
    printf("Misc: 0x%08x\n", pcie_config_hdr.Misc);
    for (int i = 0; i < 6; i++)
    {
        printf("BAR %d: Locatable: 0x%02x, Prefetchable: 0x%02x, Base_Address: 0x%08x\n", i, pcie_config_hdr.Base_Address_Registers[i].Locatable, pcie_config_hdr.Base_Address_Registers[i].Prefetchable, pcie_config_hdr.Base_Address_Registers[i].Base_Address);
    }
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

uint16_t get_dvsec_register_locator_offset(struct pci_dev *pdev)
{
    uint16_t ext_cap_off_val = 0x100;

    while (ext_cap_off_val != 0)
    {
        PCIE_EXT_CAP_HDR pcie_ext_cap_hdr;
        pci_read_block(pdev, ext_cap_off_val, &pcie_ext_cap_hdr, sizeof(pcie_ext_cap_hdr));
        printf("\nPCIE_EXT_CAP_HDR:\n PCIE_ext_cap_ID: 0x%04x, \n Cap_Ver: 0x%04x, \nNext_Cap_ofs: 0x%04x\n", pcie_ext_cap_hdr.PCIE_ext_cap_ID, pcie_ext_cap_hdr.Cap_Ver, pcie_ext_cap_hdr.Next_Cap_ofs);
        printf("DVSEC_HDR1:\n DVSEC_Vendor_ID: 0x%04x,\n DVSEC_Rev: 0x%04x,\n DVSEC_Length: 0x%04x\n", pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Vendor_ID, pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Rev, pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Length);
        printf("DVSEC_HDR2:\n DVSEC_ID: 0x%04x\n\n", pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID);
        if (pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Vendor_ID == CXL_Vendor_ID)
        {
#ifdef DEBUG
            printf("DVSEC ID is %x\n", pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID);
#endif
            if (pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID == 0x8)
            {
                printf("CXL Device found\n");
                return ext_cap_off_val;
            }
        }

        ext_cap_off_val = pcie_ext_cap_hdr.Next_Cap_ofs;
    }
    return 0;
}

uint64_t get_mailbox_base_address (struct pci_dev *pdev)
{
    uint64_t mailbox_base_address = 0;
    uint64_t base_address = 0;
    uint16_t register_locator_offset = get_dvsec_register_locator_offset(pdev);
    PCIE_CONFIG_HDR pcie_config_hdr;
    pci_read_block(pdev, 0, &pcie_config_hdr, sizeof(pcie_config_hdr));
    if (register_locator_offset != 0)
    {
        registerLocator register_locator;
        pci_read_block(pdev, register_locator_offset, &register_locator, sizeof(register_locator));

        printf("Register Locator:\n");
        printf("PCIE_ext_cap_hdr: PCIE_ext_cap_ID: 0x%04x, Cap_Ver: 0x%04x, Next_Cap_ofs: 0x%04x\n", register_locator.PCIE_ext_cap_hdr.PCIE_ext_cap_ID, register_locator.PCIE_ext_cap_hdr.Cap_Ver, register_locator.PCIE_ext_cap_hdr.Next_Cap_ofs);
        uint32_t register_block_number = get_register_block_number_from_header(&register_locator);
        for(int i=0;i<register_block_number;i++){
            if(register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Identifier != CXL_DEVICE_REGISTERS_ID){
                continue;
            }
        printf("Register Block %d: Register_BIR: 0x%02x\n", i, register_locator.Register_Block[i].Register_Offset_Low.Register_BIR);
        printf("Register Block %d: Register_Block_Identifier: 0x%02x\n", i, register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Identifier);
        printf("Register Block %d: Register_Block_Offset_Low: 0x%04x\n", i, register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Offset_Low);
        printf("Register Block %d: Register_Block_Offset_High: 0x%08x\n",i,  register_locator.Register_Block[i].Register_Offset_High.Register_Block_Offset_High);
        
        if(pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR].Locatable == 0x2){
            printf("register_locator.Register_Block[%d].Register_Offset_Low.Register_BIR=0x%x\n",i, register_locator.Register_Block[i].Register_Offset_Low.Register_BIR);
            printf("Base Address  BIR: 0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR].Base_Address);
            printf("Base Address  BIR+1:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Base_Address);
            printf("Base Address  BIR+1 Prefech:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Prefetchable);
            printf("Base Address  BIR+1 Locatable:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Locatable);
            printf("Base Address  BIR+1 Region Type:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Region_Type);
            base_address = (pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Base_Address << 4 | 
                                            pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Prefetchable << 3  | 
                                            pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Locatable << 2 |
                                            pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR+1].Region_Type ) << 32;
           // printf("Base Address before left shift: 0x%x\n", (long)base_address);
            base_address <<= 32;
            printf("Base Address: 0x%llX\n", base_address);
        }
        base_address = base_address + (pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR].Base_Address << 4 |
                                register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Offset_Low << 16 |
                                register_locator.Register_Block[i].Register_Offset_High.Register_Block_Offset_High << 32)   ;

        
        
        printf("Register Block %d: Base Address: 0x%llx\n", i, base_address);
        printf("sizeof uint64_t: %d\n", sizeof(uint64_t));
        printf("sizeof uint32_t: %d\n", sizeof(uint32_t));
        printf("sizeof uint16_t: %d\n", sizeof(uint16_t));
        printf("sizeof uint8_t: %d\n", sizeof(uint8_t));
        printf("sizeof long: %d\n", sizeof(long));

        }
    }
    DEVICE_CAPABILITIES_ARRAY_REGISTER dev_cap_arr_reg;
    MemoryDeviceRegisters mem_dev_reg;

    int fd = open("/dev/mem", O_RDWR | O_DSYNC);
    if (fd == -1) {
        perror("Error opening /dev/mem");
        exit(1);
    }

    void *map_base = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, base_address);
    if (map_base == MAP_FAILED) {
        perror("Error mapping memory");
        close(fd);
        exit(1);
    }
    my_memcpy(&dev_cap_arr_reg, map_base, sizeof(dev_cap_arr_reg));
    printf("Device Capabilities Array Register: Capability_ID: 0x%04x, Version: 0x%02x, Capabilities_Count: 0x%04x\n", dev_cap_arr_reg.Capability_ID, dev_cap_arr_reg.Version, dev_cap_arr_reg.Capabilities_Count);
    if(dev_cap_arr_reg.Capability_ID == 0x0){
        my_memcpy(&mem_dev_reg, map_base, sizeof(mem_dev_reg));
        for(int i=0;i<3;i++){
            printf("Device Capability Header %d: Capability_ID: 0x%04x, Version: 0x%02x, Offset: 0x%08x, Length: 0x%08x\n", i, mem_dev_reg.Device_Capability_Header[i].Capability_ID, mem_dev_reg.Device_Capability_Header[i].Version, mem_dev_reg.Device_Capability_Header[i].Offset, mem_dev_reg.Device_Capability_Header[i].Length);
            if(mem_dev_reg.Device_Capability_Header[i].Capability_ID == 0x2){
                printf("Offset = 0x%08x\n", mem_dev_reg.Device_Capability_Header[i].Offset);
                printf("Length = 0x%08x\n", mem_dev_reg.Device_Capability_Header[i].Length);
                mailbox_base_address = base_address + mem_dev_reg.Device_Capability_Header[i].Offset;
                printf("Mailbox Base Address: 0x%0llx\n", mailbox_base_address);
                break;
            }
        }
    }

    if (munmap(map_base, 4096) == -1) {
        perror("Error unmapping memory");
        close(fd);
        exit(1);
    }

    close(fd);
        return mailbox_base_address;
}

uint32_t get_register_block_number_from_header(registerLocator *register_locator)
{
    return ((register_locator->PCIE_ext_cap_hdr.DVSEC_hdr1.DVSEC_Length -10-2)/8);
}

int send_mailbox_command(uint64_t mailbox_base_address, uint16_t command)
{
    int fd = open("/dev/mem", O_RDWR | O_DSYNC);
    if (fd == -1) {
        perror("Error opening /dev/mem");
        exit(1);
    }
    uint64_t aligned_addr = mailbox_base_address & 0xFFFFFFFFFFFFF000;
    uint64_t mailbox_offset = mailbox_base_address - aligned_addr;
    printf("aligned_addr: 0x%llX\n", aligned_addr);
    void *map_base = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, aligned_addr);
    if (map_base == MAP_FAILED) {
        perror("Error mapping memory");
        close(fd);
        exit(1);
    }
    uint8_t *mailbox_base = (uint8_t *)map_base + (uint8_t)mailbox_offset;
    mailbox_registers *mb_regs = (mailbox_registers *)(mailbox_base);
    printf("Mailbox Base: 0x%llX\n", mailbox_base);
    if(check_mailbox_ready(mb_regs)){
        printf("Mailbox is ready\n");
        mailbox_write_command(mb_regs, command);
        mailbox_clear_payload_length(mb_regs);
        mailbox_set_payload_length(mb_regs, 0x0);
        mailbox_set_doorbell(mb_regs);
    }
    else{
        printf("Mailbox is not ready\n");
        goto close_mmap;
    }

    for(int j=0;j<100;j++){
        if(check_mailbox_ready(mb_regs)){
            printf("Mailbox is ready\n");
            uint16_t payload_length = mailbox_get_payload_length(mb_regs);
            printf("Payload Length: 0x%04x\n", payload_length);
            if(payload_length != 0){
                read_payload(mb_regs);
            }
            printf("mailbox status return code = 0x%X\n", mailbox_status_return_code(mb_regs));
            break;
        }
        else{
            printf("Mailbox is not ready\n");
            usleep(100000);
        }
    }
  
close_mmap:
    if (munmap(map_base, 4096) == -1) {
        perror("Error unmapping memory");
        close(fd);
        exit(1);
    }

    close(fd);
    return 0;
}
bool check_mailbox_ready(mailbox_registers *mb_regs)
{
    return mb_regs->MB_Control.doorbell == 0;
}

void mailbox_write_command(mailbox_registers *mb_regs, uint16_t command)
{
    mailbox_command_register cmd_reg;
    my_memcpy(&cmd_reg, &mb_regs->Command_Register, sizeof(cmd_reg));
    printf("%s:Command Register: Opcode: 0x%04x, Payload Size: 0x%04x\n", __func__,cmd_reg.opcode, cmd_reg.payload_size);
    cmd_reg.opcode = command;
    my_memcpy(&mb_regs->Command_Register, &cmd_reg, sizeof(cmd_reg));
}

void mailbox_clear_payload_length(mailbox_registers *mb_regs)
{
    mailbox_command_register cmd_reg;
    my_memcpy(&cmd_reg, &mb_regs->Command_Register, sizeof(cmd_reg));
    printf("%s:Command Register: Opcode: 0x%04x, Payload Size: 0x%04x\n", __func__,cmd_reg.opcode, cmd_reg.payload_size);
    cmd_reg.payload_size = 0;
    my_memcpy(&mb_regs->Command_Register, &cmd_reg, sizeof(cmd_reg));
}

void mailbox_set_payload_length(mailbox_registers *mb_regs, uint16_t payload_size)
{
    mailbox_command_register cmd_reg;
    my_memcpy(&cmd_reg, &mb_regs->Command_Register, sizeof(cmd_reg));
    printf("%s:Command Register: Opcode: 0x%04x, Payload Size: 0x%04x\n", __func__,cmd_reg.opcode, cmd_reg.payload_size);
    cmd_reg.payload_size = payload_size;
    my_memcpy(&mb_regs->Command_Register, &cmd_reg, sizeof(cmd_reg));
}

void mailbox_set_doorbell(mailbox_registers *mb_regs)
{
    mailbox_control_register ctrl_reg;
    my_memcpy(&ctrl_reg, &mb_regs->MB_Control, sizeof(ctrl_reg));
    printf("%s:Control Register: Doorbell: 0x%04x\n", __func__,ctrl_reg.doorbell);
    ctrl_reg.doorbell = 1;
    my_memcpy(&mb_regs->MB_Control, &ctrl_reg, sizeof(ctrl_reg));
}

uint16_t mailbox_get_payload_length(mailbox_registers *mb_regs)
{
    return mb_regs->Command_Register.payload_size;
}

void mailbox_clear_doorbell(mailbox_registers *mb_regs)
{
    mailbox_control_register ctrl_reg;
    my_memcpy(&ctrl_reg, &mb_regs->MB_Control, sizeof(ctrl_reg));
    printf("%s:Control Register: Doorbell: 0x%04x\n", __func__,ctrl_reg.doorbell);
    ctrl_reg.doorbell = 0;
    my_memcpy(&mb_regs->MB_Control, &ctrl_reg, sizeof(ctrl_reg));
}

void read_payload(mailbox_registers *mb_regs)
{   for(int i=0;i<mb_regs->Command_Register.payload_size;i++)
    printf("Payload: 0x%08x\n", mb_regs->Commmand_Payload_Registers[i]);
}

uint16_t mailbox_status_return_code(mailbox_registers *mb_regs)
{
    mailbox_status_register status_reg;
    my_memcpy(&status_reg, &mb_regs->MB_Status, sizeof(status_reg));
    printf("Status Register: Background Operation Status: 0x%04x, Return Code: 0x%04x, Vendor Specific Ext Status: 0x%04x\n", status_reg.background_operation_status, status_reg.return_code, status_reg.vendor_specific_ext_status);
    return status_reg.return_code;
}
