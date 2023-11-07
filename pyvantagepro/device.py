# -*- coding: utf-8 -*-
'''
    pyvantagepro.device
    -------------------

    Allows data query of Davis Vantage Pro2 devices

    :copyright: Copyright 2012 Salem Harrache and contributors, see AUTHORS.
    :license: GNU GPL v3.

'''
from __future__ import division, unicode_literals
import struct
from datetime import datetime, timedelta
from pylink import link_from_url, SerialLink

from .logger import LOGGER
from .utils import (cached_property, retry, bytes_to_hex,
                    ListDict, is_bytes)

from .parser import (LoopDataParserRevB, DmpHeaderParser, DmpPageParser,
                     ArchiveDataParserRevB, VantageProCRC, pack_datetime,
                     unpack_datetime, pack_dmp_date_time)


class NoDeviceException(Exception):
    '''Can not access weather station.'''
    value = __doc__


class BadAckException(Exception):
    '''No valid acknowledgement.'''
    def __str__(self):
        return self.__doc__


class BadCRCException(Exception):
    '''No valid checksum.'''
    def __str__(self):
        return self.__doc__


class BadDataException(Exception):
    '''No valid data.'''
    def __str__(self):
        return self.__doc__


class VantagePro2(object):
    '''Communicates with the station by sending commands, reads the binary
    data and parsing it into usable scalar values.

    :param link: A `PyLink` connection.
    '''

    # device reply commands
    WAKE_STR = '\n'
    WAKE_ACK = '\n\r'
    ACK = '\x06'
    NACK = '\x21'
    DONE = 'DONE\n\r'
    CANCEL = '\x18'
    ESC = '\x1b'
    OK = '\n\rOK\n\r'

    def __init__(self, link):
        self.link = link
        self.link.open()
        self._check_revision()

    @classmethod
    def from_url(cls, url, timeout=10):
        ''' Get device from url.

        :param url: A `PyLink` connection URL.
        :param timeout: Set a read timeout value.
        '''
        link = link_from_url(url)
        link.settimeout(timeout)
        return cls(link)

    @classmethod
    def from_serial(cls, port, baud_rate, timeout=10):
        ''' Get device from serial port.

        :param port: The path to the serial port.
        :param baud_rate: The baud rate for the serial connection (e.g 19200).
        :param timeout: The maximum time in seconds to wait for a response from the device.
        '''
        # Baud rate is typically 19200.
        link = SerialLink(port, baud_rate)
        link.settimeout(timeout)
        return cls(link)

    @retry(tries=3, delay=1)
    def wake_up(self):
        '''Wakeup the station console.'''
        wait_ack = self.WAKE_ACK
        LOGGER.info("try wake up console")
        self.link.write(self.WAKE_STR)
        ack = self.link.read(len(wait_ack))
        if wait_ack == ack:
            LOGGER.info(f"Check ACK: OK ({repr(ack)})")
            return True
        # Sometimes we have a 1byte shift from Vantage Pro and that's why wake up doesn't work anymore
        # We just shift another 1byte to be aligned in the serial buffer again.
        self.link.read(1)
        LOGGER.error(f"Check ACK: BAD ({repr(wait_ack)} != {repr(ack)})")
        raise NoDeviceException()

    @retry(tries=3, delay=0.5)
    def send(self, data, wait_ack=None, timeout=None):
        '''Sends data to station.

         :param data: Can be a byte array or an ASCII command. If this is
            the case for an ascii command, a <LF> will be added.

         :param wait_ack: If `wait_ack` is not None, the function must check
            that acknowledgement is the one expected.

         :param timeout: Define this timeout when reading ACK from link.
         '''
        if is_bytes(data):
            LOGGER.info(f"try send : {bytes_to_hex(data)}")
            self.link.write(data)
        else:
            LOGGER.info(f"try send : {data}")
            self.link.write(f"{data}\n")
        if wait_ack is None:
            return True
        ack = self.link.read(len(wait_ack), timeout=timeout)
        if wait_ack == ack:
            LOGGER.info(f"Check ACK: OK ({repr(ack)})")
            return True
        LOGGER.error(f"Check ACK: BAD ({repr(wait_ack)} != {repr(ack)})")
        raise BadAckException()

    @retry(tries=3, delay=1)
    def read_from_eeprom(self, hex_address, size):
        '''Reads from EEPROM the `size` number of bytes starting at the
        `hex_address`. Results are given as hex strings.'''
        self.link.write(f"EEBRD {hex_address} {size:02d}\n")
        ack = self.link.read(len(self.ACK))
        if self.ACK == ack:
            LOGGER.info(f"Check ACK: OK ({repr(ack)})")
            data = self.link.read(size + 2)  # 2 bytes for CRC
            if VantageProCRC(data).check():
                return data[:-2]
            else:
                raise BadCRCException()
        else:
            msg = f"Check ACK: BAD ({repr(self.ACK)} != {repr(ack)})"
            LOGGER.error(msg)
            raise BadAckException()

    def gettime(self):
        '''Returns the current datetime of the console.'''
        self.wake_up()
        self.send("GETTIME", self.ACK)
        data = self.link.read(8)
        return unpack_datetime(data)

    def settime(self, dtime):
        '''Set the given `dtime` on the station.'''
        self.wake_up()
        self.send("SETTIME", self.ACK)
        self.send(pack_datetime(dtime), self.ACK)

    def get_current_data(self):
        '''Returns the real-time data as a `Dict`.'''
        self.wake_up()
        self.send("LOOP 1", self.ACK)
        current_data = self.link.read(99)
        if self.RevB:
            return LoopDataParserRevB(current_data, datetime.now())
        else:
            raise NotImplementedError('Do not support RevB data format')

    def get_archives(self, start_date=None, stop_date=None):
        '''Get archive records until `start_date` and `stop_date` as
        ListDict.

        :param start_date: The beginning datetime record.

        :param stop_date: The stopping datetime record.
        '''
        generator = self._get_archives_generator(start_date, stop_date)
        archives = ListDict()
        dates = set()
        # Sets are a tad better for containments
        for item in generator:
            if item['Datetime'] not in dates:
                archives.append(item)
                dates.add(item['Datetime'])
        return archives.sorted_by('Datetime')
    
    def _process_page(self, page_number, start_date, stop_date):
        """Processes a single page of the data dump."""

        dump = self._read_dump_page(page_number)
        raw_records = dump["Records"]
        for start, end in zip(range(0, 260, 52), range(52, 261, 52)):
            raw_record = raw_records[start:end]
            record = self._parse_record(raw_record, start_date, stop_date)

            if record:
                yield record

    def _parse_record(self, raw_record, start_date, stop_date):
        """Parses a raw record, checks its validity, and returns it if it's within the date range."""
        # Parse the record based on the device revision
        record_parser = ArchiveDataParserRevB
        record = record_parser(raw_record)

        # Check record's date validity and range
        r_time = record['Datetime']
        if r_time is None:
            LOGGER.error('Invalid record detected')
            return None
        if not (start_date < r_time <= stop_date):
            LOGGER.info('Record is out of the requested datetime range')
            return None

        # Return the valid record
        return record

    def _get_archives_generator(self, start_date=None, stop_date=None):
        '''Get archive records generator until `start_date` and `stop_date`.'''
        self.wake_up()
        # Set default dates if none provided
        start_date = start_date or datetime(2001, 1, 1)
        stop_date = stop_date or datetime.now()

        # Round down start_date to the nearest archive period
        period = self.archive_period
        start_date -= timedelta(minutes=start_date.minute % period)

        # Send command to initiate data dump after start_date
        self.send("DMPAFT", self.ACK)
        packed_date = pack_dmp_date_time(start_date)
        self.link.write(packed_date)

        # Await acknowledgment with a 2-second timeout
        # Shouldn't be any lower than 2 but unsure why
        if self.link.read(len(self.ACK), timeout=2) != self.ACK:
            raise BadAckException('No acknowledgment received for the data dump request.')

        # Read and parse the dump header
        header_data = self.link.read(6)
        header = DmpHeaderParser(header_data)
        if header.crc_error:
            self.link.write(self.CANCEL)
            raise BadCRCException('Header CRC check failed.')

        # Send acknowledgment if header CRC is correct
        self.link.write(self.ACK)
        
        try:
            for i in range(header.number_of_pages):
                # Not sure if these functions need to be public.
                self._process_page(i, start_date, stop_date)
        except (BadCRCException, NotImplementedError) as e:
            LOGGER.error(f'Error during data processing: {e}')
            self.link.write(self.ESC)
            return 

        LOGGER.info('Data dump complete.')

    @cached_property
    def archive_period(self):
        '''Returns number of minutes in the archive period.'''
        return struct.unpack(b'B', self.read_from_eeprom("2D", 1))[0]

    @cached_property
    def timezone(self):
        '''Returns timezone offset as string.'''
        data = self.read_from_eeprom("14", 3)
        offset, gmt = struct.unpack(b'HB', data)
        if gmt:
            return f"GMT+{offset / 100:.2f}"
        else:
            return "Localtime"

    @cached_property
    def firmware_date(self):
        '''Return the firmware date code'''
        self.wake_up()
        self.send("VER", self.OK)
        data = self.link.read(13)
        return datetime.strptime(data.strip('\n\r'), '%b %d %Y').date()

    @cached_property
    def firmware_version(self):
        '''Returns the firmware version as string'''
        self.wake_up()
        self.send("NVER", self.OK)
        data = self.link.read(6)
        return data.strip('\n\r')

    @cached_property
    def diagnostics(self):
        '''Return the Console Diagnostics report. (RXCHECK command)'''
        self.wake_up()
        self.send("RXCHECK", self.OK)
        data = self.link.read().strip('\n\r').split(' ')
        data = [int(i) for i in data]
        return dict(total_received=data[0], total_missed=data[1],
                    resyn=data[2], max_received=data[3],
                    crc_errors=data[4])

    @retry(tries=3, delay=1)
    def _read_dump_page(self):
        '''Read, parse and check a DmpPage.'''
        raw_dump = self.link.read(267)
        if len(raw_dump) != 267:
            self.link.write(self.NACK)
            raise BadDataException()
        else:
            dump = DmpPageParser(raw_dump)
            if dump.crc_error:
                self.link.write(self.NACK)
                raise BadCRCException()
            return dump

    def _check_revision(self):
        '''Check firmware date and get data format revision.'''
        #Rev "A" firmware, dated before April 24, 2002 uses the old format.
        #Rev "B" firmware dated on or after April 24, 2002
        date = datetime(2002, 4, 24).date()
        self.RevA = self.RevB = True
        if self.firmware_date < date:
            self.RevB = False
        else:
            self.RevA = False
