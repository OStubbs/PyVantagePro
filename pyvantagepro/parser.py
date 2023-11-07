# -*- coding: utf-8 -*-
'''
    pyvantagepro.parser
    -------------------

    Allows parsing Vantage Pro2 data.

    Original Author: Patrick C. McGinty (pyweather@tuxcoder.com)
    :copyright: Copyright 2012 Salem Harrache and contributors, see AUTHORS.
    :license: GNU GPL v3.

'''
from __future__ import division, unicode_literals
import struct
from datetime import datetime
from array import array

from .compat import bytes
from .logger import LOGGER
from .utils import (cached_property, bytes_to_hex, Dict, bytes_to_binary,
                    binary_to_int, list_to_int)


class VantageProCRC(object):
    '''Implements CRC algorithm, necessary for encoding and verifying data from
    the Davis Vantage Pro unit.'''
    CRC_TABLE = (
        0x0,    0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7, 0x8108,
        0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef, 0x1231, 0x210,
        0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6, 0x9339, 0x8318, 0xb37b,
        0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de, 0x2462, 0x3443, 0x420,  0x1401,
        0x64e6, 0x74c7, 0x44a4, 0x5485, 0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee,
        0xf5cf, 0xc5ac, 0xd58d, 0x3653, 0x2672, 0x1611, 0x630,  0x76d7, 0x66f6,
        0x5695, 0x46b4, 0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d,
        0xc7bc, 0x48c4, 0x58e5, 0x6886, 0x78a7, 0x840,  0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b, 0x5af5,
        0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0xa50,  0x3a33, 0x2a12, 0xdbfd, 0xcbdc,
        0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a, 0x6ca6, 0x7c87, 0x4ce4,
        0x5cc5, 0x2c22, 0x3c03, 0xc60,  0x1c41, 0xedae, 0xfd8f, 0xcdec, 0xddcd,
        0xad2a, 0xbd0b, 0x8d68, 0x9d49, 0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13,
        0x2e32, 0x1e51, 0xe70,  0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a,
        0x9f59, 0x8f78, 0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e,
        0xe16f, 0x1080, 0xa1,   0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e, 0x2b1,
        0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256, 0xb5ea, 0xa5cb,
        0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d, 0x34e2, 0x24c3, 0x14a0,
        0x481,  0x7466, 0x6447, 0x5424, 0x4405, 0xa7db, 0xb7fa, 0x8799, 0x97b8,
        0xe75f, 0xf77e, 0xc71d, 0xd73c, 0x26d3, 0x36f2, 0x691,  0x16b0, 0x6657,
        0x7676, 0x4615, 0x5634, 0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9,
        0xb98a, 0xa9ab, 0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x8e1,  0x3882,
        0x28a3, 0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0xaf1,  0x1ad0, 0x2ab3, 0x3a92, 0xfd2e,
        0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9, 0x7c26, 0x6c07,
        0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0xcc1,  0xef1f, 0xff3e, 0xcf5d,
        0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8, 0x6e17, 0x7e36, 0x4e55, 0x5e74,
        0x2e93, 0x3eb2, 0xed1,  0x1ef0,
    )

    def __init__(self, data):
        self.data = data

    @cached_property
    def checksum(self):
        '''Return CRC calc value from raw serial data.'''
        crc = 0
        
        # Previous one-liner wasn't great for readability
        for byte in array(str('B'), bytes(self.data)):
            # Get the upper 8 bits
            upper_crc = crc >> 8

            # XOR the upper_crc with the current byte to index into the CRC table.
            table_index = upper_crc ^ byte
            table_value = self.CRC_TABLE[table_index]
            # Get the lower 8 bits of the current CRC.
            lower_crc = crc & 0xFF

            # Shift 8 bits to the left to make space for the new byte.
            shifted_lower_crc = lower_crc << 8

            # Combine the table value with the shifted lower CRC to get the new CRC value.
            crc = table_value ^ shifted_lower_crc
        return crc

    @cached_property
    def data_with_checksum(self):
        '''Return packed raw CRC from raw data.'''
        checksum = struct.pack(b'>H', self.checksum)
        return b''.join([self.data, checksum])

    def check(self):
        '''Perform CRC check on raw serial data, return true if valid.
        A valid CRC == 0.'''
        if len(self.data) != 0 and self.checksum == 0:
            LOGGER.info("Check CRC : OK")
            return True
        else:
            LOGGER.error("Check CRC : BAD")
            return False


class DataParser(Dict):
    '''Implements a reusable class for working with a binary data structure.
    It provides a named fields interface, similiar to C structures.'''

    def __init__(self, data, data_format, order='='):
        super(DataParser, self).__init__()
        self.fields, format_t = zip(*data_format)
        self.crc_error = False
        if "CRC" in self.fields:
            self.crc_error = not VantageProCRC(data).check()
        format_t = f"{order}{''.join(format_t)}"
        self.struct = struct.Struct(format=format_t)
        # save raw_bytes
        self.raw_bytes = data
        # Unpacks data from `raw_bytes` and returns a dication of named fields
        data = self.struct.unpack_from(self.raw_bytes, 0)
        self['Datetime'] = None
        self.update(Dict(zip(self.fields, data)))

    @cached_property
    def raw(self):
        return bytes_to_hex(self.raw_bytes)

    def tuple_to_dict(self, key):
        '''Convert {key<->tuple} to {key1<->value2, key2<->value2 ... }.'''
        for i, value in enumerate(self[key]):
            self[f"{key}{i + 1:02d}"] = value
        del self[key]

    def __unicode__(self):
        name = self.__class__.__name__
        return f"<{name} {self.raw}>"

    def __str__(self):
        return str(self.__unicode__())

    def __repr__(self):
        return str(self.__unicode__())


class LoopDataParserRevB(DataParser):
    '''Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2.'''
    # Loop data format (RevB)
    LOOP_FORMAT = (
        ('LOO', '3s'), ('BarTrend', 'b'), ('PacketType', 'B'),
        ('NextRec', 'H'), ('Barometer', 'H'), ('TempIn', 'h'),
        ('HumIn', 'B'), ('TempOut', 'h'), ('WindSpeed', 'B'),
        ('WindSpeed10Min', 'B'), ('WindDir', 'H'), ('ExtraTemps', '7s'),
        ('SoilTemps', '4s'), ('LeafTemps', '4s'), ('HumOut', 'B'),
        ('HumExtra', '7s'), ('RainRate', 'H'), ('UV', 'B'),
        ('SolarRad', 'H'), ('RainStorm', 'H'), ('StormStartDate', 'H'),
        ('RainDay', 'H'), ('RainMonth', 'H'), ('RainYear', 'H'),
        ('ETDay', 'H'), ('ETMonth', 'H'), ('ETYear', 'H'),
        ('SoilMoist', '4s'), ('LeafWetness', '4s'), ('AlarmIn', 'B'),
        ('AlarmRain', 'B'), ('AlarmOut', '2s'), ('AlarmExTempHum', '8s'),
        ('AlarmSoilLeaf', '4s'), ('BatteryStatus', 'B'), ('BatteryVolts', 'H'),
        ('ForecastIcon', 'B'), ('ForecastRuleNo', 'B'), ('SunRise', 'H'),
        ('SunSet', 'H'), ('EOL', '2s'), ('CRC', 'H'),
    )
    
    # Map the binary to alarm attributes
    # Using a dict with keys make any future adjustments easier over list index
    type_keys = {
        "AlarmIn": {
            0: "FallBarTrend",
            1: "RisBarTrend",
            2: "LowTemp",
            3: "HighTemp",
            4: "LowHum",
            5: "HighHum",
            6: "Time"
        },
        "AlarmRain": {
            0: 'HighRate', 
            1: '15min', 
            2: '24hour', 
            3: 'StormTotal', 
            4: 'ETDaily'
        },
        "AlarmOut72": {
            0: "LowTemp", 
            1: "HighTemp", 
            2: "WindSpeed", 
            3: "10minAvgSpeed",
            4: "LowDewpoint",
            5: "HighDewPoint",
            6: "HighHeat",
            7: "LowWindChill"
        },
        "AlarmOut73": {
            0: "HighTHSW", 
            1: "HighSolarRad", 
            2: "HighUV", 
            3: "UVDose",
            4: "UVDoseEnabled"
        },
        "AlarmExTempHum": {
            0: "LowTemp", 
            1: "HighTemp", 
            2: "LowHum", 
            3: "HighHum"
        },
        "AlarmSoilLeaf": {
            0: "LowLeafWet", 
            1: "HighLeafWet", 
            2: "LowSoilMois",
            3: "HighSoilMois", 
            4: "LowLeafTemp", 
            5: "HighLeafTemp",
            6: "LowSoilTemp", 
            7: "HighSoilTemp"
        }
    }

    def __init__(self, data, dtime):
        super(LoopDataParserRevB, self).__init__(data, self.LOOP_FORMAT)
        self['Datetime'] = dtime
        self['Barometer'] = self['Barometer'] / 1000
        self['TempIn'] = self['TempIn'] / 10
        self['TempOut'] = self['TempOut'] / 10
        self['RainRate'] = self['RainRate'] / 100
        self['RainStorm'] = self['RainStorm'] / 100
        # Given a packed storm date field, unpack and return date
        self['StormStartDate'] = self.unpack_storm_date()
        # rain totals
        self['RainDay'] = self['RainDay'] / 100
        self['RainMonth'] = self['RainMonth'] / 100
        self['RainYear'] = self['RainYear'] / 100
        # evapotranspiration totals
        self['ETDay'] = self['ETDay'] / 1000
        self['ETMonth'] = self['ETMonth'] / 100
        self['ETYear'] = self['ETYear'] / 100
        # battery statistics
        self['BatteryVolts'] = self['BatteryVolts'] * 300 / 512 / 100
        # sunrise / sunset
        self['SunRise'] = self.unpack_time(self['SunRise'])
        self['SunSet'] = self.unpack_time(self['SunSet'])
        # convert to int
        self['HumExtra'] = struct.unpack(b'7B', self['HumExtra'])
        self['ExtraTemps'] = struct.unpack(b'7B', self['ExtraTemps'])
        self['SoilMoist'] = struct.unpack(b'4B', self['SoilMoist'])
        self['SoilTemps'] = struct.unpack(b'4B', self['SoilTemps'])
        self['LeafWetness'] = struct.unpack(b'4B', self['LeafWetness'])
        self['LeafTemps'] = struct.unpack(b'4B', self['LeafTemps'])

        # Inside Alarms bits extraction, only 7 bits are used
        # Convert the byte at position X to its binary representation then to ints
        alarm_in_values = list_to_int(bytes_to_binary(self.raw_bytes[70]))
        # Rain Alarms bits extraction, only 5 bits are used
        alarm_rain_values = list_to_int(bytes_to_binary(self.raw_bytes[71]))
        alarm_out_72 = list_to_int(bytes_to_binary(self.raw_bytes[72]))
        alarm_out_73 = list_to_int(bytes_to_binary(self.raw_bytes[73]))
        # Oustide Alarms bits extraction, only 13 bits are used
        
        self.index_loop_through_data("AlarmIn", alarm_in_values, alarm_key="AlarmIn")
        self.index_loop_through_data("AlarmRain", alarm_rain_values, alarm_key="AlarmRain")
        self.index_loop_through_data("AlarmOut72", alarm_out_72, alarm_key="AlarmOut")
        self.index_loop_through_data("AlarmOut73", alarm_out_73, alarm_key="AlarmOut")

        for i in range(1, 8):
            # AlarmExTempHum bits extraction, only 3 bits are used, but 7 bytes
            data = self.raw_bytes[74 + i]
            alarm_key = f'AlarmEx{i:02}' 
            alarm_value = list_to_int(bytes_to_binary(data))
            
            # Index matches position in alarm_value
            self.index_loop_through_data("AlarmExTempHum", alarm_value, alarm_key)
            
            if i <= 4:
                # AlarmSoilLeaf 8bits, 4 bytes
                data = self.raw_bytes[81 + i]
                alarm_key = f'Alarm{i:02d}'  # Format the key once and reuse it
                alarm_value = int(bytes_to_binary(data)[0])
                # Convert once, assign multiple times
                self.loop_through_data("AlarmSoilLeaf", alarm_value, alarm_key)

        # delete unused values
        del self['LOO']
        del self['NextRec']
        del self['PacketType']
        del self['EOL']
        del self['CRC']
        # Tuple to dict
        self.tuple_to_dict("ExtraTemps")
        self.tuple_to_dict("LeafTemps")
        self.tuple_to_dict("SoilTemps")
        self.tuple_to_dict("HumExtra")
        self.tuple_to_dict("LeafWetness")
        self.tuple_to_dict("SoilMoist")
        
    def index_loop_through_data(self, type_name, alarm_value, alarm_key):
        for index, key in self.type_keys[type_name].items():
            self[f'{alarm_key}{key}'] = alarm_value[index] 
    
    def loop_through_data(self, type_name, alarm_value, alarm_key):
        for index, key in self.type_keys[type_name].items():
            self[f'{alarm_key}{key}'] = alarm_value 

    def unpack_storm_date(self):
        '''Given a packed storm date field, unpack and return date.'''
        date = bytes_to_binary(self.raw_bytes[48:50])
        year = binary_to_int(date, 0, 7) + 2000
        day = binary_to_int(date, 7, 12)
        month = binary_to_int(date, 12, 16)
        return f"{year}-{month}-{day}"
    
    def unpack_time(self, time):
        '''Given a packed time field, unpack and return "HH:MM" string.'''
        # format: HHMM, and space padded on the left.ex: "601" is 6:01 AM
        hours, minutes = divmod(time, 100)
        return f"{hours:02d}:{minutes:02d}"  # covert to "06:01"
    


class ArchiveDataParserRevB(DataParser):
    '''Parse data returned by the 'LOOP' command. It contains all of the
    real-time data that can be read from the Davis VantagePro2.'''

    ARCHIVE_FORMAT = (
        ('DateStamp',      'H'), ('TimeStamp',   'H'), ('TempOut',      'h'),
        ('TempOutHi',      'H'), ('TempOutLow',  'H'), ('RainRate',     'H'),
        ('RainRateHi',     'H'), ('Barometer',   'H'), ('SolarRad',     'H'),
        ('WindSamps',      'H'), ('TempIn',      'h'), ('HumIn',        'B'),
        ('HumOut',         'B'), ('WindAvg',     'B'), ('WindHi',       'B'),
        ('WindHiDir',      'B'), ('WindAvgDir',  'B'), ('UV',           'B'),
        ('ETHour',         'B'), ('SolarRadHi',  'H'), ('UVHi',         'B'),
        ('ForecastRuleNo', 'B'), ('LeafTemps',  '2s'), ('LeafWetness', '2s'),
        ('SoilTemps',     '4s'), ('RecType',     'B'), ('ExtraHum',    '2s'),
        ('ExtraTemps',    '3s'), ('SoilMoist',  '4s'),
    )

    def __init__(self, data):
        super(ArchiveDataParserRevB, self).__init__(data, self.ARCHIVE_FORMAT)
        self['raw_datestamp'] = bytes_to_binary(self.raw_bytes[0:4])
        self['Datetime'] = unpack_dmp_date_time(self['DateStamp'],
                                                self['TimeStamp'])
        del self['DateStamp']
        del self['TimeStamp']
        self['TempOut'] = self['TempOut'] / 10
        self['TempOutHi'] = self['TempOutHi'] / 10
        self['TempOutLow'] = self['TempOutLow'] / 10
        self['Barometer'] = self['Barometer'] / 1000
        self['TempIn'] = self['TempIn'] / 10
        self['UV'] = self['UV'] / 10
        self['ETHour'] = self['ETHour'] / 1000
        '''
        self['WindHiDir'] = int(self['WindHiDir'] * 22.5)
        self['WindAvgDir'] = int(self['WindAvgDir'] * 22.5)
        '''
        SoilTempsValues = struct.unpack(b'4B', self['SoilTemps'])
        self['SoilTemps'] = tuple((t - 90) for t in SoilTempsValues)

        self['ExtraHum'] = struct.unpack(b'2B', self['ExtraHum'])
        self['SoilMoist'] = struct.unpack(b'4B', self['SoilMoist'])
        LeafTempsValues = struct.unpack(b'2B', self['LeafTemps'])
        self['LeafTemps'] = tuple((t - 90) for t in LeafTempsValues)
        self['LeafWetness'] = struct.unpack(b'2B', self['LeafWetness'])
        ExtraTempsValues = struct.unpack(b'3B', self['ExtraTemps'])
        self['ExtraTemps'] = tuple((t - 90) for t in ExtraTempsValues)
        self.tuple_to_dict("SoilTemps")
        self.tuple_to_dict("LeafTemps")
        self.tuple_to_dict("ExtraTemps")
        self.tuple_to_dict("SoilMoist")
        self.tuple_to_dict("LeafWetness")
        self.tuple_to_dict("ExtraHum")


class DmpHeaderParser(DataParser):
    DMP_FORMAT = (
        ('Pages',   'H'),  ('Offset',   'H'),  ('CRC',     'H'),
    )

    def __init__(self, data):
        super(DmpHeaderParser, self).__init__(data, self.DMP_FORMAT)


class DmpPageParser(DataParser):
    DMP_FORMAT = (
        ('Index',   'B'),  ('Records',   '260s'),  ('unused',     '4B'),
        ('CRC',   'H'),
    )

    def __init__(self, data):
        super(DmpPageParser, self).__init__(data, self.DMP_FORMAT)


def pack_dmp_date_time(d):
    '''Pack `datetime` to DateStamp and TimeStamp VantagePro2 with CRC.'''
    vpdate = d.day + d.month * 32 + (d.year - 2000) * 512
    vptime = 100 * d.hour + d.minute
    data = struct.pack(b'HH', vpdate, vptime)
    return VantageProCRC(data).data_with_checksum


def unpack_dmp_date_time(date, time):
    '''Unpack `date` and `time` to datetime'''
    if date != 0xffff and time != 0xffff:
        day = date & 0x1f                     # 5 bits
        month = (date >> 5) & 0x0f            # 4 bits
        year = ((date >> 9) & 0x7f) + 2000    # 7 bits
        hour, min_ = divmod(time, 100)
        return datetime(year, month, day, hour, min_)


def pack_datetime(dtime):
    '''Returns packed `dtime` with CRC.'''
    data = struct.pack(b'>BBBBBB', dtime.second, dtime.minute,
                       dtime.hour, dtime.day, dtime.month, dtime.year - 1900)
    return VantageProCRC(data).data_with_checksum


def unpack_datetime(data):
    '''Return unpacked datetime `data` and check CRC.'''
    VantageProCRC(data).check()
    s, m, h, day, month, year = struct.unpack(b'>BBBBBB', data[:6])
    return datetime(year + 1900, month, day, h, m, s)
