#include<stdio.h>
#include<stdint.h>
#include<string.h>
#include "cxl_mailbox.h"
#include "info_status.h"
#include "cxl_cci_events.h"

void get_events_records(mailbox_base_address)
{
    // Allocate memory for the request payload
    get_event_records_input_payload_t request_payload = {.event_log = EVENT_LOG_INFORMATIONAL};

    //Calculate the size of the request payload
    uint32_t request_payload_size = sizeof(get_event_records_input_payload_t);

    // Allocate memory for the response payload
    uint32_t *response_payload = (uint32_t *)malloc(request_payload_size+sizeof(get_event_records_output_payload_t));
    memset(response_payload, 0, sizeof(get_event_records_output_payload_t));
    memcpy(response_payload, &request_payload, request_payload_size);
    uint16_t ret_code = 0;

    int ret = send_mailbox_command(mailbox_base_address, GET_EVENT_RECORDS_OPCODE, 
                                   (uint16_t)request_payload_size, 
                                   (uint64_t)response_payload,  
                                   &ret_code);
    
    if (ret == 0){
        printf("\t\tGet Event Records\n");
        // Print the values of get_event_records_output_payload_t
        get_event_records_output_payload_t *output_payload = (get_event_records_output_payload_t *)(response_payload);
        printf("\t\tFlags: 0x%02x\n", output_payload->flags);
        printf("\t\toverflow: 0x%02x\n", output_payload->overflow_error_count);
        printf("\t\t first overflow event timestamp: 0x%x\n", output_payload->first_overflow_event_timestamp);
        printf("\t\tlast overflow event timestamp: 0x%x\n", output_payload->last_overflow_event_timestamp);
        printf("\t\ttotal event record count: 0x%x\n", output_payload->event_record_count);
        
    }
    else{
        printf("\t\tFailed to get Event Records\n");
    }
    print_ret_code(ret_code);
    free(response_payload);
}
