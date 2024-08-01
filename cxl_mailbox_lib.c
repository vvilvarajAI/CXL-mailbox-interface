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
static mailbox_registers *mb_regs;
static int fd_mailbox;
static void *map_base;
extern unsigned int debug_mode;

void *my_memcpy(void *dest, const void *src, size_t n);
void convert_timestamp_to_human_readable(uint32_t *payload, uint16_t payload_size);
void print_ret_code(uint16_t ret_code);
void cxl_mailbox_get_timestamp(uint64_t mailbox_base_address);

#define DEBUG_PRINT(fmt, ...)       \
    if (debug_mode == 0)            \
    {                               \
        do                          \
        {                           \
        } while (0);                \
    }                               \
    else                            \
    {                               \
        printf(fmt, ##__VA_ARGS__); \
    }

void *my_memcpy(void *dest, const void *src, size_t n)
{
    char *d = (char *)dest;
    const char *s = (char *)src;

    size_t num_words = n / sizeof(int);
    size_t remaining_bytes = n % sizeof(int);

    for (size_t i = 0; i < num_words; i++)
    {
        *((int *)d) = *((int *)s);
        d += sizeof(int);
        s += sizeof(int);
    }

    for (size_t i = 0; i < remaining_bytes; i++)
    {
        *d++ = *s++;
    }

    return dest;
}

void convert_timestamp_to_human_readable(uint32_t *payload, uint16_t payload_size)
{
    printf("Timestamp: 0x%08x%08x\n", payload[1], payload[0]);
    time_t timestamp;
    DEBUG_PRINT("sizeof time_t = %d", sizeof(time_t));
    memcpy(&timestamp, payload, sizeof(time_t));
    struct tm *timeinfo = localtime(&timestamp);
    printf("Timestamp: %s", asctime(timeinfo));
}

void print_ret_code(uint16_t ret_code)
{
    DEBUG_PRINT("Return Code: 0x%04x==", ret_code);
    switch (ret_code)
    {
    case SUCCESS:
        DEBUG_PRINT("Success\n");
        break;
    case BACKGROUND_COMMAND_STARTED:
        DEBUG_PRINT("Background Command Started\n");
        break;
    case INVALID_INPUT:
        DEBUG_PRINT("Invalid Input\n");
        break;
    case UNSUPPORTED:
        DEBUG_PRINT("Unsupported\n");
        break;
    case INTERNAL_ERROR:
        DEBUG_PRINT("Internal Error\n");
        break;
    case RETRY_REQUIRED:
        DEBUG_PRINT("Retry Required\n");
        break;
    case BUSY:
        DEBUG_PRINT("Busy\n");
        break;
    case MEDIA_DISABLED:
        DEBUG_PRINT("Media Disabled\n");
        break;
    case FW_TRANSFER_IN_PROGRESS:
        DEBUG_PRINT("FW Transfer In Progress\n");
        break;
    case FW_TRANSFER_OUT_OF_ORDER:
        DEBUG_PRINT("FW Transfer Out of Order\n");
        break;
    case FW_AUTHENTICATION_FAILED:
        DEBUG_PRINT("FW Authentication Failed\n");
        break;
    case INVALID_SLOT:
        DEBUG_PRINT("Invalid Slot\n");
        break;
    case ACTIVATION_FAILED_ROLLBACK:
        DEBUG_PRINT("Activation Failed Rollback\n");
        break;
    case ACTIVATION_FAILED_RESET:
        DEBUG_PRINT("Activation Failed Reset\n");
        break;
    case INVALID_HANDLE:
        DEBUG_PRINT("Invalid Handle\n");
        break;
    case INVALID_PHYSICAL_ADDRESS:
        DEBUG_PRINT("Invalid Physical Address\n");
        break;
    case INJECT_POISON_LIMIT_REACHED:
        DEBUG_PRINT("Inject Poison Limit Reached\n");
        break;
    case PERMANENT_MEDIA_FAILURE:
        DEBUG_PRINT("Permanent Media Failure\n");
        break;
    case ABORTED:
        DEBUG_PRINT("Aborted\n");
        break;
    case INVALID_SECURITY_STATE:
        DEBUG_PRINT("Invalid Security State\n");
        break;
    case INCORRECT_PASSPHRASE:
        DEBUG_PRINT("Incorrect Passphrase\n");
        break;
    case UNSUPPORTED_MAILBOX:
        DEBUG_PRINT("Unsupported Mailbox\n");
        break;
    case INVALID_PAYLOAD_LENGTH:
        DEBUG_PRINT("Invalid Payload Length\n");
        break;
    default:
        DEBUG_PRINT("Unknown Return Code\n");
        break;
    }
}

void cxl_mailbox_get_timestamp(uint64_t mailbox_base_address)
{
    uint32_t *payload = (uint32_t *)malloc(CXL_TIMESTAMP_SIZE);
    uint16_t payload_size = CXL_TIMESTAMP_SIZE;
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, 0x300, &payload_size, payload, &ret_code); // 0x300 is GET_TIMESTAMP command
    print_ret_code(ret_code);
    convert_timestamp_to_human_readable(payload, payload_size);
    free(payload);
}

void cxl_mailbox_clear_timestamp(uint64_t mailbox_base_address)
{
    uint32_t *payload = NULL;
    uint16_t payload_size = 0;
    uint16_t ret_code = 0;
    int ret = send_mailbox_command(mailbox_base_address, 0x301, &payload_size, payload, &ret_code); // 0x301 is SET_TIMESTAMP command
    print_ret_code(ret_code);
}

void print_config_header(struct pci_dev *pdev)
{
    DEBUG_PRINT("Configuration Header:\n");
    PCIE_CONFIG_HDR pcie_config_hdr;
    pci_read_block(pdev, 0, &pcie_config_hdr, sizeof(pcie_config_hdr));
    DEBUG_PRINT("Vendor ID: 0x%04x\n", pcie_config_hdr.Vendor_ID);
    DEBUG_PRINT("Device ID: 0x%04x\n", pcie_config_hdr.Device_ID);
    DEBUG_PRINT("Command: 0x%04x\n", pcie_config_hdr.Command);
    DEBUG_PRINT("Status: 0x%04x\n", pcie_config_hdr.Status);
    DEBUG_PRINT("Rev ID: 0x%02x\n", pcie_config_hdr.Rev_ID);
    DEBUG_PRINT("Class Code: 0x%06x\n", pcie_config_hdr.Class_Code);
    DEBUG_PRINT("Misc: 0x%08x\n", pcie_config_hdr.Misc);
    for (int i = 0; i < 6; i++)
    {
        DEBUG_PRINT("BAR %d: Locatable: 0x%02x, Prefetchable: 0x%02x, Base_Address: 0x%08x\n", i, pcie_config_hdr.Base_Address_Registers[i].Locatable, pcie_config_hdr.Base_Address_Registers[i].Prefetchable, pcie_config_hdr.Base_Address_Registers[i].Base_Address);
    }
}

void print_extended_config(struct pci_dev *pdev)
{
    // Print the configuration space
    DEBUG_PRINT("Configuration Space:\n");
    unsigned char config_space[4096];
    pci_read_block(pdev, 0, config_space, sizeof(config_space));
    for (int i = 0; i < sizeof(config_space); i++)
    {
        DEBUG_PRINT("%02X ", config_space[i]);
        if ((i + 1) % 16 == 0)
        {
            DEBUG_PRINT("\n");
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
        DEBUG_PRINT("\nPCIE_EXT_CAP_HDR:\n PCIE_ext_cap_ID: 0x%04x, \n Cap_Ver: 0x%04x, \nNext_Cap_ofs: 0x%04x\n", pcie_ext_cap_hdr.PCIE_ext_cap_ID, pcie_ext_cap_hdr.Cap_Ver, pcie_ext_cap_hdr.Next_Cap_ofs);
        DEBUG_PRINT("DVSEC_HDR1:\n DVSEC_Vendor_ID: 0x%04x,\n DVSEC_Rev: 0x%04x,\n DVSEC_Length: 0x%04x\n", pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Vendor_ID, pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Rev, pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Length);
        DEBUG_PRINT("DVSEC_HDR2:\n DVSEC_ID: 0x%04x\n\n", pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID);
        if (pcie_ext_cap_hdr.DVSEC_hdr1.DVSEC_Vendor_ID == CXL_Vendor_ID)
        {
#ifdef DEBUG
            DEBUG_PRINT("DVSEC ID is %x\n", pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID);
#endif
            if (pcie_ext_cap_hdr.DVSEC_hdr2.DVSEC_ID == 0x8)
            {
                DEBUG_PRINT("CXL Device found\n");
                return ext_cap_off_val;
            }
        }

        ext_cap_off_val = pcie_ext_cap_hdr.Next_Cap_ofs;
    }
    return 0;
}

uint64_t get_mailbox_base_address(struct pci_dev *pdev)
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

        DEBUG_PRINT("Register Locator:\n");
        DEBUG_PRINT("PCIE_ext_cap_hdr: PCIE_ext_cap_ID: 0x%04x, Cap_Ver: 0x%04x, Next_Cap_ofs: 0x%04x\n", register_locator.PCIE_ext_cap_hdr.PCIE_ext_cap_ID, register_locator.PCIE_ext_cap_hdr.Cap_Ver, register_locator.PCIE_ext_cap_hdr.Next_Cap_ofs);
        uint32_t register_block_number = get_register_block_number_from_header(&register_locator);
        for (int i = 0; i < register_block_number; i++)
        {
            if (register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Identifier != CXL_DEVICE_REGISTERS_ID)
            {
                continue;
            }
            DEBUG_PRINT("Register Block %d: Register_BIR: 0x%02x\n", i, register_locator.Register_Block[i].Register_Offset_Low.Register_BIR);
            DEBUG_PRINT("Register Block %d: Register_Block_Identifier: 0x%02x\n", i, register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Identifier);
            DEBUG_PRINT("Register Block %d: Register_Block_Offset_Low: 0x%04x\n", i, register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Offset_Low);
            DEBUG_PRINT("Register Block %d: Register_Block_Offset_High: 0x%08x\n", i, register_locator.Register_Block[i].Register_Offset_High.Register_Block_Offset_High);

            base_address = pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR].Base_Address << 4 |
                           register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Offset_Low << 16 |
                           register_locator.Register_Block[i].Register_Offset_High.Register_Block_Offset_High << 32;
            if (pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR].Locatable == 0x2)
            {
                DEBUG_PRINT("register_locator.Register_Block[%d].Register_Offset_Low.Register_BIR=0x%x\n", i, register_locator.Register_Block[i].Register_Offset_Low.Register_BIR);
                DEBUG_PRINT("Base Address  BIR: 0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR].Base_Address);
                DEBUG_PRINT("Base Address  BIR+1:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Base_Address);
                DEBUG_PRINT("Base Address  BIR+1 Prefech:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Prefetchable);
                DEBUG_PRINT("Base Address  BIR+1 Locatable:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Locatable);
                DEBUG_PRINT("Base Address  BIR+1 Region Type:  0x%x\n", pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Region_Type);
                base_address = (pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Base_Address << 4 |
                                pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Prefetchable << 3 |
                                pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Locatable << 2 |
                                pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR + 1].Region_Type)
                               << 32;
                base_address <<= 32;
            }
            base_address = base_address + (pcie_config_hdr.Base_Address_Registers[register_locator.Register_Block[i].Register_Offset_Low.Register_BIR].Base_Address << 4 |
                                           register_locator.Register_Block[i].Register_Offset_Low.Register_Block_Offset_Low << 16 |
                                           register_locator.Register_Block[i].Register_Offset_High.Register_Block_Offset_High << 32);
            DEBUG_PRINT("Register Block %d: Base Address: 0x%llx\n", i, base_address);
        }
    }
    DEVICE_CAPABILITIES_ARRAY_REGISTER dev_cap_arr_reg;
    MemoryDeviceRegisters mem_dev_reg;

    int fd = open("/dev/mem", O_RDWR | O_DSYNC);
    if (fd == -1)
    {
        perror("Error opening /dev/mem");
        exit(1);
    }

    void *map_base = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, base_address);
    if (map_base == MAP_FAILED)
    {
        perror("Error mapping memory");
        close(fd);
        exit(1);
    }
    my_memcpy(&dev_cap_arr_reg, map_base, sizeof(dev_cap_arr_reg));
    DEBUG_PRINT("Device Capabilities Array Register: Capability_ID: 0x%04x, Version: 0x%02x, Capabilities_Count: 0x%04x\n", dev_cap_arr_reg.Capability_ID, dev_cap_arr_reg.Version, dev_cap_arr_reg.Capabilities_Count);
    if (dev_cap_arr_reg.Capability_ID == 0x0)
    {
        my_memcpy(&mem_dev_reg, map_base, sizeof(mem_dev_reg));
        for (int i = 0; i < 3; i++)
        {
            DEBUG_PRINT("Device Capability Header %d: Capability_ID: 0x%04x, Version: 0x%02x, Offset: 0x%08x, Length: 0x%08x\n", i, mem_dev_reg.Device_Capability_Header[i].Capability_ID, mem_dev_reg.Device_Capability_Header[i].Version, mem_dev_reg.Device_Capability_Header[i].Offset, mem_dev_reg.Device_Capability_Header[i].Length);
            if (mem_dev_reg.Device_Capability_Header[i].Capability_ID == 0x2)
            {
                DEBUG_PRINT("Offset = 0x%08x\n", mem_dev_reg.Device_Capability_Header[i].Offset);
                DEBUG_PRINT("Length = 0x%08x\n", mem_dev_reg.Device_Capability_Header[i].Length);
                mailbox_base_address = base_address + mem_dev_reg.Device_Capability_Header[i].Offset;
                break;
            }
        }
    }

    if (munmap(map_base, 4096) == -1)
    {
        perror("Error unmapping memory");
        close(fd);
        exit(1);
    }

    close(fd);
    return mailbox_base_address;
}

uint32_t get_register_block_number_from_header(registerLocator *register_locator)
{
    return ((register_locator->PCIE_ext_cap_hdr.DVSEC_hdr1.DVSEC_Length - 10 - 2) / 8);
}

void map_mailbox_registers(uint64_t mailbox_base_address)
{
    fd_mailbox = open("/dev/mem", O_RDWR | O_DSYNC);
    if (fd_mailbox == -1)
    {
        perror("Error opening /dev/mem");
        exit(1);
    }
    uint64_t aligned_addr = mailbox_base_address & 0xFFFFFFFFFFFFF000;
    uint64_t mailbox_offset = mailbox_base_address - aligned_addr;
    DEBUG_PRINT("aligned_addr: 0x%llX\n", aligned_addr);
    map_base = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd_mailbox, aligned_addr);
    if (map_base == MAP_FAILED)
    {
        perror("Error mapping memory");
        close(fd_mailbox);
        exit(1);
    }
    uint8_t *mailbox_base = (uint8_t *)map_base + (uint8_t)mailbox_offset;
    DEBUG_PRINT("Mailbox Base: 0x%08x\n", mailbox_base);
    mb_regs = (mailbox_registers *)(mailbox_base);
}

int close_mmap()
{
    if (munmap(map_base, 4096) == -1)
    {
        perror("Error unmapping memory");
        close(fd_mailbox);
        exit(1);
    }

    close(fd_mailbox);
    return 0;
}

int send_mailbox_command(uint64_t mailbox_base_address, uint16_t command, uint16_t *payload_size, uint32_t *payload, uint16_t *ret_code)
{
    if (mb_regs == NULL)
        map_mailbox_registers(mailbox_base_address);

    if (check_mailbox_ready(mb_regs))
    {
        DEBUG_PRINT("Mailbox is ready\n");
        mailbox_write_command(mb_regs, command);
        mailbox_clear_payload_length(mb_regs);

        if (*payload_size != 0)
        {
            mailbox_set_payload_length(mb_regs, *payload_size);
            mailbox_write_payload(mb_regs, *payload_size, payload);
        }
        else
        {
            mailbox_set_payload_length(mb_regs, 0);
        }

        mailbox_set_doorbell(mb_regs);
    }
    else
    {
        DEBUG_PRINT("Mailbox is not ready\n");
        close_mmap();
        return -1; // Return error if mailbox is not ready initially
    }

    for (int j = 0; j < 100; j++)
    {
        if (check_mailbox_ready(mb_regs))
        {
            DEBUG_PRINT("Mailbox is ready\n");
            uint16_t payload_length = mailbox_get_payload_length(mb_regs);
            DEBUG_PRINT("Payload Length: 0x%04x\n", payload_length);

            if (payload_length != 0)
            {
                if (payload == NULL || *payload_size == 0)
                {
                    *payload_size = payload_length;
                    if (payload != NULL)
                        free(payload);
                    payload = (uint32_t *)malloc(*payload_size);
                    if (payload == NULL)
                    {
                        DEBUG_PRINT("Memory allocation failed\n");
                        return -1; // Return error if memory allocation fails
                    }
                }
                *ret_code = mailbox_status_return_code(mb_regs);
                return 0; // Return success
            }
        }
        else
        {
            DEBUG_PRINT("Mailbox is not ready\n");
            usleep(100000); // Sleep for 100 milliseconds
        }
    }

    return -1; // Return error if mailbox is not ready after 100 attempts
}
bool check_mailbox_ready(mailbox_registers *mb_regs)
{
    return mb_regs->MB_Control.doorbell == 0;
}

void mailbox_write_command(mailbox_registers *mb_regs, uint16_t command)
{
    mailbox_command_register cmd_reg;
    my_memcpy(&cmd_reg, &mb_regs->Command_Register, sizeof(cmd_reg));
    cmd_reg.opcode = command;
    my_memcpy(&mb_regs->Command_Register, &cmd_reg, sizeof(cmd_reg));
    DEBUG_PRINT("%s:Command Register: Opcode: 0x%04x, Payload Size: 0x%04x\n", __func__, cmd_reg.opcode, cmd_reg.payload_size);
}

void mailbox_clear_payload_length(mailbox_registers *mb_regs)
{
    mailbox_command_register cmd_reg;
    my_memcpy(&cmd_reg, &mb_regs->Command_Register, sizeof(cmd_reg));
    cmd_reg.payload_size = 0;
    my_memcpy(&mb_regs->Command_Register, &cmd_reg, sizeof(cmd_reg));
    DEBUG_PRINT("%s:Command Register: Opcode: 0x%04x, Payload Size: 0x%04x\n", __func__, cmd_reg.opcode, cmd_reg.payload_size);
}

void mailbox_set_payload_length(mailbox_registers *mb_regs, uint16_t payload_size)
{
    mailbox_command_register cmd_reg;
    my_memcpy(&cmd_reg, &mb_regs->Command_Register, sizeof(cmd_reg));
    cmd_reg.payload_size = payload_size;
    my_memcpy(&mb_regs->Command_Register, &cmd_reg, sizeof(cmd_reg));
    DEBUG_PRINT("%s:Command Register: Opcode: 0x%04x, Payload Size: 0x%04x\n", __func__, cmd_reg.opcode, cmd_reg.payload_size);
}

void mailbox_set_doorbell(mailbox_registers *mb_regs)
{
    mailbox_control_register ctrl_reg;
    my_memcpy(&ctrl_reg, &mb_regs->MB_Control, sizeof(ctrl_reg));
    ctrl_reg.doorbell = 1;
    my_memcpy(&mb_regs->MB_Control, &ctrl_reg, sizeof(ctrl_reg));
    DEBUG_PRINT("%s:Control Register: Doorbell: 0x%04x\n", __func__, ctrl_reg.doorbell);
}

uint16_t mailbox_get_payload_length(mailbox_registers *mb_regs)
{
    return mb_regs->Command_Register.payload_size;
}

void mailbox_clear_doorbell(mailbox_registers *mb_regs)
{
    mailbox_control_register ctrl_reg;
    my_memcpy(&ctrl_reg, &mb_regs->MB_Control, sizeof(ctrl_reg));
    DEBUG_PRINT("%s:Control Register: Doorbell: 0x%04x\n", __func__, ctrl_reg.doorbell);
    ctrl_reg.doorbell = 0;
    my_memcpy(&mb_regs->MB_Control, &ctrl_reg, sizeof(ctrl_reg));
}

void read_payload(mailbox_registers *mb_regs, uint16_t payload_length, uint32_t *payload)
{
    for (int i = 0; i < payload_length; i++)
    {
        payload[i] = mb_regs->Commmand_Payload_Registers[i];
        DEBUG_PRINT("%s:Payload: 0x%08x\n", __func__, mb_regs->Commmand_Payload_Registers[i]);
    }
}

void mailbox_write_payload(mailbox_registers *mb_regs, uint16_t payload_length, uint32_t *payload)
{
    for (int i = 0; i < payload_length; i++)
    {
        mb_regs->Commmand_Payload_Registers[i] = payload[i];
        DEBUG_PRINT("%s:Payload: 0x%08x\n", __func__, mb_regs->Commmand_Payload_Registers[i]);
    }
}

uint16_t mailbox_status_return_code(mailbox_registers *mb_regs)
{
    mailbox_status_register status_reg;
    my_memcpy(&status_reg, &mb_regs->MB_Status, sizeof(status_reg));
    DEBUG_PRINT("Status Register: Background Operation Status: 0x%04x, Return Code: 0x%04x, Vendor Specific Ext Status: 0x%04x\n", status_reg.background_operation_status, status_reg.return_code, status_reg.vendor_specific_ext_status);
    return status_reg.return_code;
}