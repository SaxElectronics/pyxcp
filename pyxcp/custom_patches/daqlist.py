# -*- coding: utf-8 -*-
from collections import defaultdict
from collections import deque


class DaqDataHandler:
    def __init__(self):
        self.daq_data_locks = {}
        self.odt_entry_counters = defaultdict(int)
        self.sorted_daq_data = defaultdict(deque)
        self.complete_samples = defaultdict(deque)
        self.data_ready_flags = {}
        self.received_samples = defaultdict(int)
        self.data_flags = defaultdict(bool)
        self.accumulating_entries = defaultdict(list)  # Temporarily stores current sample data

    def _process_daq_data_simple(self, payload):
        """
        Processes and sorts incoming DAQ (Data Acquisition) data payloads.

        Args:
            payload (bytes): The incoming DAQ data payload. The first byte represents the ODT entry number and the
                            second byte represents the DAQ list number.
        """
        odt_entry_number = payload[0]  # First byte is the ODT entry number
        daq_list_number = payload[1]  # Second byte is the DAQ list number

        # Append the payload data (excluding the first two bytes) to the main deque
        data_to_append = payload[2:]
        self.sorted_daq_data[daq_list_number].append((odt_entry_number, data_to_append))

        # Debug: Log the appended data
        print(f"Appended data to DAQ list {daq_list_number}, ODT entry {odt_entry_number}: {data_to_append}")

        # # Check for wraparound
        if odt_entry_number < self.odt_entry_counters[daq_list_number]:
            #     # Wraparound detected, append the accumulated sample to the complete samples deque
            self.complete_samples[daq_list_number].append(self.accumulating_entries[daq_list_number])
            #     print(f"Appended complete sample to DAQ list {daq_list_number}")
            #     # Reset the accumulating entries for the next sample
            self.accumulating_entries[daq_list_number] = []

        self.accumulating_entries[daq_list_number].append((odt_entry_number, data_to_append))

        # Update the ODT entry counter for the DAQ list
        self.odt_entry_counters[daq_list_number] = odt_entry_number

    def pop_odtdata_for_daqlist_stored_by_entry(self, daq_list_number):
        """
        Pops the complete sample point data for a specific DAQ list number.

        Args:
            daq_list_number (int): The DAQ list number to process.

        Returns:
            list: A list of tuples containing the ODT entry number and the data for the sample point.
        """
        if daq_list_number in self.sorted_daq_data and self.sorted_daq_data[daq_list_number]:
            return self.sorted_daq_data[daq_list_number].popleft()
        return None

    def pop_received_daq_data_stored_by_sample_point(self, daq_list_number):
        """
        Pops the complete sample point data for a specific DAQ list number.

        Args:
            daq_list_number (int): The DAQ list number to process.

        Returns:
            list: A list of tuples containing the ODT entry number and the data for the sample point.
        """
        if daq_list_number in self.complete_samples and self.complete_samples[daq_list_number]:
            return self.complete_samples[daq_list_number].popleft()
        return None
