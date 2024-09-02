#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pci/pci.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <time.h>

#define CXL_Vendor_ID 0x1E98
#define CXL_DEVICE_REGISTERS_ID 0x03

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

typedef struct mailbox_capabilities_register {
    uint32_t payload_size : 4;
    uint32_t mb_doorbell_int_capable : 1;
    uint32_t background_command_complete_interupt_capable : 1;
    uint32_t intr_msg_number : 4;
    uint32_t mb_ready_time :8;
    uint32_t type : 4;
    uint32_t reserved : 10;
} mailbox_capabilities_register;

typedef struct mailbox_control_register {
    uint32_t doorbell : 1;       // 1-bit field named 'doorbell' 
    uint32_t doorbell_interrupt_mode : 1;  // 1-bit field named 'doorbell_interrupt_mode'
    uint32_t background_command_complete_interupt : 1;  // 1-bit field named 'background_command_complete_interupt'
    uint32_t reserved : 29;      // Reserved bits
} mailbox_control_register;

typedef struct mailbox_command_register {
    uint64_t opcode :16;
    uint64_t payload_size: 10;
    uint64_t reserved :38;
}mailbox_command_register;

typedef struct mailbox_status_register {
    uint64_t background_operation_status :1;
    uint64_t reserved :31;
    uint64_t return_code :16;
    uint64_t vendor_specific_ext_status :16;
}mailbox_status_register;

typedef struct mailbox_background_command_status_register {
    uint64_t last_opcode :16;
    uint64_t percent_complete :7;
    uint64_t reserved :9;
    uint64_t return_code :16;
    uint64_t vendor_specific_ext_status :16;
}mailbox_background_command_status_register;

typedef struct mailbox_registers {
    mailbox_capabilities_register MB_Capabilities;
    mailbox_control_register MB_Control;
    mailbox_command_register Command_Register;
    mailbox_status_register MB_Status;
    mailbox_background_command_status_register Background_Command_Status_Register;
    uint32_t Commmand_Payload_Registers[512]; 
} mailbox_registers;

enum mailbox_ret_codes{
    SUCCESS                     = 0x0000,
    BACKGROUND_COMMAND_STARTED  = 0x0001,
    INVALID_INPUT               = 0x0002,
    UNSUPPORTED                 = 0x0003,
    INTERNAL_ERROR              = 0x0004,
    RETRY_REQUIRED              = 0x0005,
    BUSY                        = 0x0006,
    MEDIA_DISABLED              = 0x0007,
    FW_TRANSFER_IN_PROGRESS     = 0x0008,
    FW_TRANSFER_OUT_OF_ORDER    = 0x0009,
    FW_AUTHENTICATION_FAILED    = 0x000A,
    INVALID_SLOT                = 0x000B,
    ACTIVATION_FAILED_ROLLBACK  = 0x000C,
    ACTIVATION_FAILED_RESET     = 0x000D,
    INVALID_HANDLE              = 0x000E,
    INVALID_PHYSICAL_ADDRESS    = 0x000F,
    INJECT_POISON_LIMIT_REACHED = 0x0010,
    PERMANENT_MEDIA_FAILURE     = 0x0011,
    ABORTED                     = 0x0012,
    INVALID_SECURITY_STATE      = 0x0013,
    INCORRECT_PASSPHRASE        = 0x0014,
    UNSUPPORTED_MAILBOX         = 0x0015,
    INVALID_PAYLOAD_LENGTH      = 0x0016
};

void print_config_header(struct pci_dev *pdev);
void cxl_mailbox_get_timestamp(uint64_t mailbox_base_address);
void print_extended_config(struct pci_dev *pdev);
uint16_t get_dvsec_register_locator_offset(struct pci_dev *pdev);
uint64_t get_mailbox_base_address (struct pci_dev *pdev);
uint32_t get_register_block_number_from_header(registerLocator *register_locator);
int send_mailbox_command(uint64_t mailbox_base_address, uint16_t command,uint16_t *payload_size, uint32_t *payload, uint16_t *ret_code);
bool check_mailbox_ready(mailbox_registers *mb_regs);
void mailbox_write_payload(mailbox_registers *mb_regs, uint16_t payload_length, uint32_t *payload);
void read_payload(mailbox_registers *mb_regs, uint16_t payload_length, uint32_t *payload);
void mailbox_write_command(mailbox_registers *mb_regs, uint16_t command);
void mailbox_clear_payload_length(mailbox_registers *mb_regs);
void mailbox_set_payload_length(mailbox_registers *mb_regs, uint16_t payload_size);
void mailbox_set_doorbell(mailbox_registers *mb_regs);

uint16_t mailbox_get_payload_length(mailbox_registers *mb_regs);
uint16_t mailbox_status_return_code(mailbox_registers *mb_regs);