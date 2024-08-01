#pragma once
void CCI_commands(uint64_t mailbox_base_address, uint16_t host_id, uint8_t region_count, uint8_t starting_region_index, uint8_t region_id, uint64_t region_block_size, uint8_t sanitize_on_release, uint32_t extent_count, uint32_t starting_extent_index, uint8_t selection_policy, uint8_t region_number, uint64_t length, uint64_t tag, dynamic_capacity_extent extent_list[2], uint8_t flags, uint32_t max_tags);

void cci_commands(uint64_t mailbox_base_address);
