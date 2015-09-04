# Copyright (c) 2015, The Linux Foundation. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and
# only version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

from print_out import print_out_str
from parser_util import register_parser, RamParser


@register_parser(
    '--thermal-info', 'Useful information from thermal data structures')
class Thermal_info(RamParser):

    def print_thermal_info(
            self, sensor_dbg_info_start_address, ram_dump,
            time_stamp, sensor_mapping):
        for ncpu in ram_dump.iter_cpus():
            self.output_file.write(
                "------------------------------------------------\n")
            self.output_file.write(
                " TEMPERATURE ENTRIES FOR CPU:{0} \n".format(
                    int(ncpu)))
            self.output_file.write(
                "------------------------------------------------\n")
            cpu_sensor_addr = sensor_dbg_info_start_address + \
                sensor_mapping[ncpu]
            for i in range(0, 10):
                temp = self.ramdump.read_word(cpu_sensor_addr + (i * 8), True)
                time = self.ramdump.read_word(
                    cpu_sensor_addr + time_stamp + (i * 8), True)
                self.output_file.write(
                    "Temperature reading -  {0} ".format(int(temp)))
                self.output_file.write("TimeStamp - {0}\n".format(long(time)))

    def tmdev_data(self, ram_dump):
        sensor_mapping = []
        self.output_file.write("Thermal sensor data \n")

        tmdev = self.ramdump.address_of('tmdev')
        tmdev_address = self.ramdump.read_word(tmdev, True)
        sensor_dbg_info_size = ram_dump.sizeof('struct tsens_sensor_dbg_info')
        sensor_dbg_info = self.ramdump.field_offset(
            'struct tsens_tm_device',
            'sensor_dbg_info')
        time_stamp = self.ramdump.field_offset(
            'struct tsens_sensor_dbg_info',
            'time_stmp')
        cpus_sensor = self.ramdump.address_of('cpus')
        cpus_sensor_size = ram_dump.sizeof('struct cpu_info')
        sensor_id_offset = self.ramdump.field_offset(
            'struct cpu_info',
            'sensor_id')

        if not all((tmdev, sensor_dbg_info_size, sensor_dbg_info,
                    time_stamp, cpus_sensor, cpus_sensor_size,
                    sensor_id_offset)):
            self.output_file.write("Not supported for this target yet  :-( \n")
            return

        for i in ram_dump.iter_cpus():
            cpu_sensor_id_address = cpus_sensor + sensor_id_offset
            sensor_id = self.ramdump.read_u32(cpu_sensor_id_address, True)
            cpus_sensor = cpus_sensor + cpus_sensor_size
            sensor_mapping.append((sensor_id - 1) * sensor_dbg_info_size)

        self.print_thermal_info(
            (tmdev_address + sensor_dbg_info),
            ram_dump,
            time_stamp,
            sensor_mapping)

    def parse(self):
        self.output_file = self.ramdump.open_file('thermal_info.txt')

        self.tmdev_data(self.ramdump)

        self.output_file.close()
        print_out_str("--- Wrote the output to thermal_info.txt")
