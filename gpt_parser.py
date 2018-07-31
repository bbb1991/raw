#!/usr/bin/python


# Author : n0fate
# E-Mail rapfer@gmail.com, n0fate@live.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#
# Using structures defined in Wikipedia('http://en.wikipedia.org/wiki/GUID_Partition_Table')


import hashlib
import struct
import sys
import uuid
import zlib

LBA_SIZE = 512

PRIMARY_GPT_LBA = 1

OFFSET_CRC32_OF_HEADER = 16
GPT_HEADER_FORMAT = '<8sIIIIQQQQ16sQIII420x'
GUID_PARTITION_ENTRY_FORMAT = '<16s16sQQQ72s'


# gpt parser code start

def get_lba(fhandle, entry_number, count):
    fhandle.seek(LBA_SIZE * entry_number)
    fbuf = fhandle.read(LBA_SIZE * count)

    return fbuf


def unsigned32(n):
    return n & 0xFFFFFFFF


def get_gpt_header(fhandle, fbuf, lba):
    fbuf = get_lba(fhandle, lba, 1)
    
    gpt_header = struct.unpack(GPT_HEADER_FORMAT, fbuf[:512])
    
    crc32_header_value = calc_header_crc32(fbuf, gpt_header[2])

    return gpt_header, crc32_header_value, fbuf


def make_nop(byte):
    nop_code = 0x00
    pk_nop_code = struct.pack('=B', nop_code)
    nop = pk_nop_code * byte
    return nop


def calc_header_crc32(fbuf, header_size):
    nop = make_nop(4)

    clean_header = fbuf[:OFFSET_CRC32_OF_HEADER] + nop + fbuf[OFFSET_CRC32_OF_HEADER + 4:header_size]

    crc32_header_value = unsigned32(zlib.crc32(clean_header))
    return crc32_header_value


def an_gpt_header(gpt_header, crc32_header_value):
    signature = gpt_header[0]
    revision = gpt_header[1]
    headersize = gpt_header[2]
    crc32_header = gpt_header[3]
    reserved = gpt_header[4]
    currentlba = gpt_header[5]
    backuplba = gpt_header[6]
    first_use_lba_for_partitions = gpt_header[7]
    last_use_lba_for_partitions = gpt_header[8]
    disk_guid = uuid.UUID(bytes_le=gpt_header[9])
    part_entry_start_lba = gpt_header[10]
    num_of_part_entry = gpt_header[11]
    size_of_part_entry = gpt_header[12]
    crc32_of_partition_array = gpt_header[13]
    print('[+] Primary GPT header')
    print(' [-] Signature: %s' % signature.decode())
    print(' [-] Revision: %d' % revision)
    print(' [-] Header Size: %d' % headersize)
    if crc32_header_value == crc32_header:
        print(' [-] CRC32 of header: %X (VALID) => Real: %X' % (crc32_header, crc32_header_value))
    else:
        print(' [-] WARNING!! CRC32 of header: %X (INVALID) => Real: %X' % (crc32_header, crc32_header_value))
    print(' [-] Current LBA: 0x%.8X' % currentlba)
    print(' [-] Backup LBA: 0x%.8X' % backuplba)
    print(' [-] First usable LBA for partitions: 0x%.8X' % first_use_lba_for_partitions)
    print(' [-] Last usable LBA for partitions: 0x%.8X' % last_use_lba_for_partitions)
    print(' [-] Disk GUID: %s' % str(disk_guid).upper())
    print(' [-] Partition entries starting LBA: 0x%.8X' % part_entry_start_lba)
    print(' [-] Number of partition entries: %d' % num_of_part_entry)
    print(' [-] Size of partition entry: 0x%.8X' % size_of_part_entry)
    print(' [-] CRC32 of partition array: 0x%.8X' % crc32_of_partition_array)


# get partition entry
def get_part_entry(fbuf, offset, size):
    return struct.unpack(GUID_PARTITION_ENTRY_FORMAT, fbuf[offset:offset + size])


def get_part_table_area(f, gpt_header):
    part_entry_start_lba = gpt_header[10]
    first_use_lba_for_partitions = gpt_header[7]
    fbuf = get_lba(f, part_entry_start_lba, first_use_lba_for_partitions - part_entry_start_lba)

    return fbuf


def part_attribute(value):
    if value == 0:
        return 'System Partition'
    elif value == 2:
        return 'Legacy BIOS Bootable'
    elif value == 60:
        return 'Read-Only'
    elif value == 62:
        return 'Hidden'
    elif value == 63:
        return 'Do not automount'
    else:
        return 'UNKNOWN'


def check_partition_guid_type(guid):
    partitions = {
        '024DEE41-33E7-11D3-9D69-0008C781F39F': ('MBR partition scheme', 'None'),
        'C12A7328-F81F-11D2-BA4B-00A0C93EC93B': ('EFI System partition', 'None'),
        '21686148-6449-6E6F-744E-656564454649': ('BIOS Boot partition', 'None'),
        'E3C9E316-0B5C-4DB8-817D-F92DF00215AE': ('Microsoft Reserved Partition', 'Windows'),
        'EBD0A0A2-B9E5-4433-87C0-68B6B72699C7': ('Basic data partition / Linux filesystem data', 'Windows / Linux'),
        '5808C8AA-7E8F-42E0-85D2-E1E90434CFB3': ('Logical Disk Manager metadata partition', 'Windows'),
        'AF9B60A0-1431-4F62-BC68-3311714A69AD': ('Logical Disk Manager data partition', 'Windows'),
        'DE94BBA4-06D1-4D40-A16A-BFD50179D6AC': ('Windows Recovery Environment', 'Windows'),
        '37AFFC90-EF7D-4E96-91C3-2D7AE055B174': ('IBM General Parallel File System (GPFS) partition', 'Windows'),
        'DB97DBA9-0840-4BAE-97F0-FFB9A327C7E1': ('Cluster metadata partition', 'Windows'),
        '75894C1E-3AEB-11D3-B7C1-7B03A0000000': ('Data partition', 'HP-UX'),
        'E2A1E728-32E3-11D6-A682-7B03A0000000': ('Service partition', 'HP-UX'),
        '0FC63DAF-8483-4772-8E79-3D69D8477DE4': ('Linux filesystem data', 'Linux'),
        'A19D880F-05FC-4D3B-A006-743F0F84911E': ('RAID partition', 'Linux'),
        '0657FD6D-A4AB-43C4-84E5-0933C84B4F4F': ('Swap partition', 'Linux'),
        'E6D6D379-F507-44C2-A23C-238F2A3DF928': ('Logical Volume Manager (LVM) partition', 'Linux'),
        '8DA63339-0007-60C0-C436-083AC8230908': ('Reserved', 'Linux'),
        '83BD6B9D-7F41-11DC-BE0B-001560B84F0F': ('Boot partition', 'FreeBSD'),
        '516E7CB4-6ECF-11D6-8FF8-00022D09712B': ('Data partition', 'FreeBSD'),
        '516E7CB5-6ECF-11D6-8FF8-00022D09712B': ('Swap partition', 'FreeBSD'),
        '516E7CB6-6ECF-11D6-8FF8-00022D09712B': ('Unix File System(UFS) partition', 'FreeBSD'),
        '516E7CB8-6ECF-11D6-8FF8-00022D09712B': ('Vinum volume manager partition', 'FreeBSD'),
        '516E7CBA-6ECF-11D6-8FF8-00022D09712B': ('ZFS partition', 'FreeBSD'),
        '48465300-0000-11AA-AA11-00306543ECAC': ('Hierarchical File System Plus (HFS+) partition', 'Mac OS X'),
        '55465300-0000-11AA-AA11-00306543ECAC': ('Apple UFS', 'Mac OS X'),
        '6A898CC3-1DD2-11B2-99A6-080020736631': ('ZFS / /usr partition', 'Mac OS X / Solaris'),
        '52414944-0000-11AA-AA11-00306543ECAC': ('Apple RAID partition', 'Mac OS X'),
        '52414944-5F4F-11AA-AA11-00306543ECAC': ('Apple RAID partition, offline', 'Mac OS X'),
        '426F6F74-0000-11AA-AA11-00306543ECAC': ('Apple Boot partition', 'Mac OS X'),
        '4C616265-6C00-11AA-AA11-00306543ECAC': ('Apple Label', 'Mac OS X'),
        '5265636F-7665-11AA-AA11-00306543ECAC': ('Apple TV Recovery partition', 'Mac OS X'),
        '53746F72-6167-11AA-AA11-00306543ECAC': ('Apple Core Storage (i.e. Lion FileVault) partition', 'Mac OS X'),
        '6A82CB45-1DD2-11B2-99A6-080020736631': ('Boot partition', 'Solaris'),
        '6A85CF4D-1DD2-11B2-99A6-080020736631': ('Root partition', 'Solaris'),
        '6A87C46F-1DD2-11B2-99A6-080020736631': ('Swap partition', 'Solaris'),
        '6A8B642B-1DD2-11B2-99A6-080020736631': ('Backup partition', 'Solaris'),
        '6A8EF2E9-1DD2-11B2-99A6-080020736631': ('/var partition', 'Solaris'),
        '6A90BA39-1DD2-11B2-99A6-080020736631': ('/home partition', 'Solaris'),
        '6A9283A5-1DD2-11B2-99A6-080020736631': ('Alternate sector', 'Solaris'),
        '6A945A3B-1DD2-11B2-99A6-080020736631': ('Reserved partition', 'Solaris'),
        '6A9630D1-1DD2-11B2-99A6-080020736631': ('Reserved partition', 'Solaris'),
        '6A980767-1DD2-11B2-99A6-080020736631': ('Reserved partition', 'Solaris'),
        '6A96237F-1DD2-11B2-99A6-080020736631': ('Reserved partition', 'Solaris'),
        '6A8D2AC7-1DD2-11B2-99A6-080020736631': ('Reserved partition', 'Solaris'),
        '49F48D32-B10E-11DC-B99B-0019D1879648': ('Swap partition', 'NetBSD'),
        '49F48D5A-B10E-11DC-B99B-0019D1879648': ('FFS partition', 'NetBSD'),
        '49F48D82-B10E-11DC-B99B-0019D1879648': ('LFS partition', 'NetBSD'),
        '49F48DAA-B10E-11DC-B99B-0019D1879648': ('RAID partition', 'NetBSD'),
        '2DB519C4-B10F-11DC-B99B-0019D1879648': ('Concatenated partition', 'NetBSD'),
        '2DB519EC-B10F-11DC-B99B-0019D1879648': ('Encrypted partition', 'NetBSD'),
        'FE3A2A5D-4F32-41A7-B725-ACCC3285A309': ('ChromeOS kernel', 'Chrome OS'),
        '3CB8E202-3B7E-47DD-8A3C-7FF2A13CFCEC': ('ChromeOS rootfs', 'Chrome OS'),
        '2E0A753D-9E48-43B0-8337-B15192CB1B5E': ('ChromeOS future use', 'Chrome OS'),
        'AA31E02A-400F-11DB-9590-000C2911D1B8': ('VMFS partition', 'VMware ESX'),
        '9D275380-40AD-11DB-BF97-000C2911D1B8': ('vmkcore crash partition', 'VMware ESX'),
        '85D5E45E-237C-11E1-B4B3-E89A8F7FC3A7': ('Boot partition', 'MidnightBSD'),
        '85D5E45A-237C-11E1-B4B3-E89A8F7FC3A7': ('Data partition', 'MidnightBSD'),
        '85D5E45B-237C-11E1-B4B3-E89A8F7FC3A7': ('Swap partition', 'MidnightBSD'),
        '0394Ef8B-237E-11E1-B4B3-E89A8F7FC3A7': ('Unix File System (UFS) partition', 'MidnightBSD'),
        '85D5E45C-237C-11E1-B4B3-E89A8F7FC3A7': ('Vinum volume manager partition', 'MidnightBSD'),
        '85D5E45D-237C-11E1-B4B3-E89A8F7FC3A7': ('ZFS partition', 'MidnightBSD'),
        'DEA0BA2C-CBDD-4805-B4F9-F428251C3E98': ('SBL1 partition', 'Qualcomm'),
        '8C6B52AD-8A9E-4398-AD09-AE916E53AE2D': ('SBL2 partition', 'Qualcomm'),
        '05E044DF-92F1-4325-B69E-374A82E97D6E': ('SBL3 partition', 'Qualcomm'),
        '400FFDCD-22E0-47E7-9A23-F16ED9382388': ('APPSBL partition', 'Qualcomm'),
        'A053AA7F-40B8-4B1C-BA08-2F68AC71A4F4': ('QSEE partition', 'Qualcomm'),
        'E1A6A689-0C8D-4CC6-B4E8-55A4320FBD8A': ('QHEE partition', 'Qualcomm'),
        '098DF793-D712-413D-9D4E-89D711772228': ('RPM partition', 'Qualcomm'),
        'D4E0D938-B7FA-48C1-9D21-BC5ED5C4B203': ('WDOG debug partition', 'Qualcomm'),
        '20A0C19C-286A-42FA-9CE7-F64C3226A794': ('DDR partition', 'Qualcomm'),
        'A19F205F-CCD8-4B6D-8F1E-2D9BC24CFFB1': ('CDT partition', 'Qualcomm'),
        '66C9B323-F7FC-48B6-BF96-6F32E335A428': ('RAM dump partition', 'Qualcomm'),
        '303E6AC3-AF15-4C54-9E9B-D9A8FBECF401': ('SEC partition', 'Qualcomm'),
        'C00EEF24-7709-43D6-9799-DD2B411E7A3C': ('PMIC config data partition', 'Qualcomm'),
        '82ACC91F-357C-4A68-9C8F-689E1B1A23A1': ('MISC? partition', 'Qualcomm'),
        '10A0C19C-516A-5444-5CE3-664C3226A794': ('LIMITS? partition', 'Qualcomm'),
        '65ADDCF4-0C5C-4D9A-AC2D-D90B5CBFCD03': ('DEVINFO? partition', 'Qualcomm'),
        'E6E98DA2-E22A-4D12-AB33-169E7DEAA507': ( 'APDP? partition', 'Qualcomm'),
        'ED9E8101-05FA-46B7-82AA-8D58770D200B': ('MSADP? partition', 'Qualcomm'),
        '11406F35-1173-4869-807B-27DF71802812': ('DPO? partition', 'Qualcomm'),
        'DF24E5ED-8C96-4B86-B00B-79667DC6DE11': ('SPARE1? partition', 'Qualcomm'),
        '6C95E238-E343-4BA8-B489-8681ED22AD0B': ('PERSIST? partition', 'Qualcomm'),
        'EBBEADAF-22C9-E33B-8F5D-0E81686A68CB': ('MODEMST1 partition', 'Qualcomm'),
        '0A288B1F-22C9-E33B-8F5D-0E81686A68CB': ('MODEMST2 partition', 'Qualcomm'),
        '638FF8E2-22C9-E33B-8F5D-0E81686A68CB': ('FSG? partition', 'Qualcomm'),
        '57B90A16-22C9-E33B-8F5D-0E81686A68CB': ('FSC? partition', 'Qualcomm'),
        '2C86E742-745E-4FDD-BFD8-B6A7AC638772': ('SSD? partition', 'Qualcomm'),
        'DE7D4029-0F5B-41C8-AE7E-F6C023A02B33': ('KEYSTORE? partition', 'Qualcomm'),
        '323EF595-AF7A-4AFA-8060-97BE72841BB9': ('ENCRYPT? partition', 'Qualcomm'),
        '45864011-CF89-46E6-A445-85262E065604': ('EKSST? partition', 'Qualcomm'),
        '8ED8AE95-597F-4C8A-A5BD-A7FF8E4DFAA9': ('RCT partition', 'Qualcomm'),
        '7C29D3AD-78B9-452E-9DEB-D098D542F092': ('SPARE2? partition', 'Qualcomm'),
        '9D72D4E4-9958-42DA-AC26-BEA7A90B0434': ('RECOVERY? partition', 'Qualcomm'),
        '4627AE27-CFEF-48A1-88FE-99C3509ADE26': ('raw_resources? partition', 'Qualcomm'),
        '20117F86-E985-4357-B9EE-374BC1D8487D': ('BOOT partition', 'Qualcomm'),
        '379D107E-229E-499D-AD4F-61F5BCF87BD4': ('SPARE3? partition', 'Qualcomm'),
        '86A7CB80-84E1-408C-99AB-694F1A410FC7': ('FOTA? partition', 'Qualcomm'),
        '0DEA65E5-A676-4CDF-823C-77568B577ED5': ('SPARE4? partition', 'Qualcomm'),
        '97D7B011-54DA-4835-B3C4-917AD6E73D74': ('SYSTEM? partition', 'Qualcomm'),
        '5594C694-C871-4B5F-90B1-690A6F68E0F7': ('CACHE? partition', 'Qualcomm'),
        '1B81E7E6-F50D-419B-A739-2AEEF8DA3335': ('USERDATA? partition', 'Qualcomm'),
        '98523EC6-90FE-4C67-B50A-0FC59ED6F56D': ('LG Advanced Flasher partition', 'LG'),
        '4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709': ('Root Partition (x86-64)', "Linux"),
        '44479540-F297-41B2-9AF7-D131D5F0458A': ('Root Partition (x86)', "Linux"),
        '69DAD710-2CE4-4E3C-B16C-21A1D49ABED3': ("Root Partition (32-bit ARM)", "Linux"),
        'B921B045-1DF0-41C3-AF44-4C6F280D3FAE': ("Root Partition (64-bit ARM)", "Linux"),
        '993D8D3D-F80E-4225-855A-9DAF8ED7EA97': ("Root Partition (Itanium/IA-64)", "Linux"),
        '933AC7E1-2EB4-4F13-B844-0E14E2AEF915': ("/home", "Linux"),
        '3B8F8425-20E0-4F3B-907F-1A25A76F98E8': ("/srv Server Data Partition", "Linux"),
    }

    return partitions.get(guid, ('unknown partition', 'UNKNOWN'))


# analysis partition table
def an_part_table(partition_table, gpt_header):
    num_of_part_entry = gpt_header[11]
    size_of_part_entry = gpt_header[12]
    crc32_of_partition_array = gpt_header[13]

    part_list = []

    crc32_part_value = unsigned32(zlib.crc32(partition_table))
    print('')
    print('[+] Partition table')
    if crc32_part_value == crc32_of_partition_array:
        print(' [-] CRC32 Check : %.8X (VALID)' % crc32_part_value)
    else:
        print(' [-] WARNING!! CRC32 Check : %.8X (INVALID)' % crc32_part_value)

    for part_entry_num in range(0, num_of_part_entry):
        part_entry = get_part_entry(partition_table, size_of_part_entry * part_entry_num, size_of_part_entry)

        # first LBA, last LBA
        if part_entry[2] == 0 or part_entry[3] == 0:
            continue

        part_list.append(part_entry)

    count = 1
    for part_entry in part_list:
        print('')
        print(' [-] Partition %d' % count)
        print('  [-] Partition type GUID: %s' % str(uuid.UUID(bytes_le=part_entry[0])).upper())
        print('      => Partition type: %s, %s' % (
            check_partition_guid_type(str(uuid.UUID(bytes_le=part_entry[0])).upper())))
        print('  [-] Unique partition GUID: %s' % str(uuid.UUID(bytes_le=part_entry[1])).upper())
        print('  [-] First LBA: %d' % part_entry[2])
        print('      => Disk Offset: 0x%.8X (%s)' % (part_entry[2] * LBA_SIZE, sizeof_fmt(part_entry[2] * LBA_SIZE)))
        print('  [-] Last LBA: %d' % part_entry[3])
        print('      => Disk Offset: 0x%.8X (%s)' % (part_entry[3] * LBA_SIZE, sizeof_fmt(part_entry[3] * LBA_SIZE)))
        print('  [-] Attribute flags: %d, %s' % (part_entry[4], part_attribute(part_entry[4])))
        print('  [-] Partition size: (%s)' % (sizeof_fmt(part_entry[3] * LBA_SIZE - part_entry[2] * LBA_SIZE)))
        print('  [-] Partition Name: %s' % str(part_entry[5]))
        count += 1


def main():
    try:
        f = open(sys.argv[1], 'rb')
    except IndexError:
        print("Please, give me a disk image!")
        print("Example:", "python gpt_parser.py disk_image.py")
        sys.exit(-1)
    except IOError:
        print('[+] WARNING!! Can not open disk image.')
        sys.exit(-1)

    fbuf = ''

    # Protected MBR
    # You can use mbr_parser.py at http://gleeda.blogspot.com/2012/04/mbr-parser.html

    # Primary GPT header
    gpt_header, crc32_header_value, gpt_buf = get_gpt_header(f, fbuf, PRIMARY_GPT_LBA)
    an_gpt_header(gpt_header, crc32_header_value)

    h = hashlib.md5()
    h.update(gpt_buf)
    print('')
    print('[+] Primary GPT header md5: %s' % h.hexdigest())

    print('')

    # Partition entries
    fbuf = get_part_table_area(f, gpt_header)
    an_part_table(fbuf, gpt_header)

    h = hashlib.md5()
    h.update(fbuf)
    print('')
    print('[+] Partition table md5: %s' % h.hexdigest())

    # backup GPT header
    print('')
    try:
        gpt_header, crc32_header_value, gpt_buf = get_gpt_header(f, fbuf, gpt_header[6])
        an_gpt_header(gpt_header, crc32_header_value)

        h = hashlib.md5()
        h.update(gpt_buf)
        print('')
        print('[+] Backup GPT header md5: %s' % h.hexdigest())
    except struct.error:
        print('[+] WARNING!! Backup GPT header can not found. Check your disk image.')
        print('[+] WARNING!! Backup GPT header offset: 0x%.8X' % (gpt_header[6] * LBA_SIZE))

    f.close()


def sizeof_fmt(num, suffix='B'):
    """
    function, that will return bytes in human readable format.
    For example:
        >>> sizeof_fmt(168963795964)
            '157.4GiB'

    :param num: bytes, which need to be converted to human readable format.
    :param suffix:
    :return:
    """
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f %s %s" % (num, 'Yi', suffix)


if __name__ == "__main__":
    main()
