from enum import IntEnum
from os.path import isfile
from struct import pack, unpack, calcsize
from hashlib import md5, sha1, sha256, sha512
from binascii import hexlify as _hexlify, unhexlify
from io import BytesIO, SEEK_CUR, SEEK_SET, SEEK_END
from ctypes import Structure, BigEndianStructure, sizeof

MD5_DIGEST_LEN = 16
SHA1_DIGEST_LEN = 20
SHA256_DIGEST_LEN = 32
SHA512_DIGEST_LEN = 64

def hexlify(b: (bytes, bytearray)) -> str:
    return _hexlify(b).decode("utf8")

class Endian(IntEnum):
    LITTLE = 0
    BIG = 1
    NETWORK = 2
    NATIVE = 3

class Type(IntEnum):
    BYTE = 0
    UBYTE = 1
    BYTE_ARRAY = 2
    UBYTE_ARRAY = 3
    UINT8 = 4
    UINT16 = 5
    UINT32 = 6
    UINT64 = 7
    INT8 = 8
    INT16 = 9
    INT32 = 10
    INT64 = 11
    VARINT = 12
    FLOAT32 = 13
    SINGLE = 14
    FLOAT64 = 15
    DOUBLE = 16
    STRING = 17
    CSTRING = 18
    STRUCT = 19

class StreamSection(object):
    offset: int = 0
    size: int = 0

    def __init__(self, offset: int, size: int) -> None:
        self.reset()
        self.offset = offset
        self.size = size

    def reset(self) -> None:
        self.offset = 0
        self.size = 0

class StreamIO(object):
    stream = None
    endian = None

    # I/O functions
    read_func = None
    write_func = None

    # attributes
    can_seek = False
    can_tell = False

    def __init__(self, stream = None, endian: Endian = Endian.LITTLE):
        self.reset()
        self.set_stream(stream)
        self.set_endian(endian)
        self.set_io_funcs()

    # reset
    def reset(self) -> None:
        self.stream = None
        self.endian = None
        self.read_func = None
        self.write_func = None
        self.can_seek = False
        self.can_tell = False

    # add with functionality
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # shortcuts
    def __len__(self) -> int:
        return self.length()

    def __bytes__(self) -> bytes:
        return self.getvalue()

    # utilities
    def set_stream(self, stream) -> None:
        """
        Set stream to read/write from/to
        :param stream: The stream to interact with
        :return: None
        """
        if stream is None:
            self.stream = BytesIO()
        elif isinstance(stream, bytes) or isinstance(stream, bytearray):
            self.stream = BytesIO(stream)
        elif isinstance(stream, str) and isfile(stream):
            self.stream = open(stream, "rb+")
        else:
            self.stream = stream
        self.can_seek = self.stream.seekable()
        self.can_tell = self.stream.seekable()

    def set_endian(self, endian: Endian) -> None:
        """
        Set the endian you want to use for reading/writing data in the stream
        :param endian: LITTLE, BIG, NETWORK, or NATIVE
        :return: None
        """
        endian = int(endian)
        endians = ["<", ">", "!", "@"]
        if endian in range(0, len(endians)):
            self.endian = endians[endian]

    def set_read_func(self, name: str) -> None:  #, *param_types):
        """
        Set the function name in the stream of the read function
        :param name: The name of the read function
        :return: None
        """
        if hasattr(self.stream, name):
            self.read_func = getattr(self.stream, name)

    def set_write_func(self, name: str) -> None:  #, *param_types):
        """
        Set the function name in the stream of the write function
        :param name: The name of the write function
        :return: None
        """
        if hasattr(self.stream, name):
            self.write_func = getattr(self.stream, name)

    def set_io_funcs(self, read_name: str = "read", write_name: str = "write") -> None:
        """
        Set the read/write function names in the stream
        :param read_name: The name of the read function
        :param write_name: The name of the write function
        :return: None
        """
        self.set_read_func(read_name)
        self.set_write_func(write_name)

    def tell(self) -> int:
        """
        Tell the current position of the stream if supported
        :return: The position of the stream
        """
        if self.can_tell:
            return self.stream.tell()
        raise NotImplementedError("tell isn't implemented in the specified stream!")

    def seek(self, index: int, whence: int = SEEK_SET) -> int:
        """
        Jump to a position in the stream if supported
        :param index: The offset to jump to
        :param whence: Index is interpreted relative to the position indicated by whence (SEEK_SET, SEEK_CUR, and SEEK_END in io library)
        :return: The new absolute position
        """
        if self.can_seek:
            return self.stream.seek(index, whence)
        raise NotImplementedError("seek isn't implemented in the specified stream!")

    def seek_start(self) -> int:
        """
        Jump to the beginning of the stream if supported
        :return: The new absolute position
        """
        return self.stream.seek(0)

    def seek_end(self) -> int:
        """
        Jump to the end of the stream if supported
        :return: The new absolute position
        """
        return self.stream.seek(0, SEEK_END)

    def length(self) -> int:
        """
        Get the length of the stream if supported
        :return: The total length of the stream
        """
        prev_loc = self.seek_end()
        stream_len = self.tell()
        self.seek(prev_loc)
        return stream_len

    def getvalue(self) -> (bytes, bytearray):
        """
        Get the stream's output
        :return: The stream's data as bytes or bytearray
        """
        return self.stream.getvalue()

    def getbuffer(self) -> (bytes, bytearray):
        """
        Get the stream's buffer
        :return: The stream's buffer as bytes or bytearray
        """
        return self.stream.getbuffer()

    def flush(self) -> None:
        """
        Write the data to the stream
        :return: None
        """
        return self.stream.flush()

    def close(self) -> None:
        """
        Close the stream
        :return: None
        """
        self.stream.close()

    # base I/O methods
    def read(self, num: int = -1) -> (bytes, bytearray):
        if num <= 0:
            return self.read_func()
        return self.read_func(num)

    def write(self, data: (bytes, bytearray, int)) -> int:
        if isinstance(data, int):
            data = bytes([data])
        return self.write_func(data)

    def stream_unpack(self, fmt: str) -> (tuple, list):
        fmt = self.endian + fmt
        return unpack(fmt, self.read(calcsize(fmt)))

    def stream_pack(self, fmt: str, *values) -> int:
        fmt = self.endian + fmt
        return self.write(pack(fmt, *values))

    # bytes
    def read_byte(self) -> int:
        return self.stream_unpack("b")[0]

    def read_byte_at(self, offset: int) -> int:
        loc = self.tell()
        self.seek(offset)
        output = self.read_byte()
        self.seek(loc)
        return output

    def read_bytes(self, num: int) -> (tuple, list):
        return self.stream_unpack(str(num) + "b")

    def read_bytes_at(self, offset: int, num: int) -> (tuple, list):
        loc = self.tell()
        self.seek(offset)
        output = self.read_bytes(num)
        self.seek(loc)
        return output

    def write_byte(self, value: int) -> int:
        return self.stream_pack("b", value)

    def write_byte_at(self, offset: int, value: int) -> int:
        loc = self.tell()
        self.seek(offset)
        output = self.write_byte(value)
        self.seek(loc)
        return output

    def write_bytes(self, values: (bytes, bytearray)) -> int:
        return self.stream_pack(str(len(values)) + "b", *values)

    def write_bytes_at(self, offset: int, values: (bytes, bytearray)) -> int:
        loc = self.tell()
        self.seek(offset)
        output = self.write_bytes(values)
        self.seek(loc)
        return output

    # ubytes
    def read_ubyte(self) -> int:
        return self.stream_unpack("B")[0]

    def read_ubyte_at(self, offset: int) -> int:
        loc = self.tell()
        self.seek(offset)
        output = self.read_ubyte()
        self.seek(loc)
        return output

    def read_ubytes(self, num: int) -> (bytes, bytearray):
        return self.stream_unpack(str(num) + "s")[0]

    def read_ubytes_at(self, offset: int, num: int) -> (tuple, list):
        loc = self.tell()
        self.seek(offset)
        output = self.read_ubytes(num)
        self.seek(loc)
        return output

    def write_ubyte(self, value: int):
        return self.stream_pack("B", value)

    def write_ubyte_at(self, offset: int, value: int) -> int:
        loc = self.tell()
        self.seek(offset)
        output = self.write_ubyte(value)
        self.seek(loc)
        return output

    def write_ubytes(self, values: (bytes, bytearray)) -> int:
        return self.stream_pack(str(len(values)) + "s", values)

    def write_ubytes_at(self, offset: int, values: (bytes, bytearray)) -> int:
        loc = self.tell()
        self.seek(offset)
        output = self.write_ubytes(values)
        self.seek(loc)
        return output

    def load_from_buffer(self, data: (bytes, bytearray)) -> int:
        return self.write_ubytes(data)

    # boolean
    def read_bool(self) -> bool:
        return self.stream_unpack("?")[0]

    def read_bool_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "?")

    def write_bool(self, value: bool) -> int:
        return self.stream_pack("?", value)

    def write_bool_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "?", *values)

    # int16/short
    def read_int16(self) -> int:
        return self.stream_unpack("h")[0]

    def read_short(self) -> int:
        return self.read_int16()

    def read_int16_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "h")

    def read_short_array(self, num: int) -> tuple:
        return self.read_int16_array(num)

    def write_int16(self, value: int) -> int:
        return self.stream_pack("h", value)

    def write_short(self, value: int) -> int:
        return self.write_int16(value)

    def write_int16_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "h", *values)

    def write_short_array(self, values: (list, tuple)) -> int:
        return self.write_int16_array(values)

    # uint16/ushort
    def read_uint16(self) -> int:
        return self.stream_unpack("H")[0]

    def read_ushort(self) -> int:
        return self.read_uint16()

    def read_uint16_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "H")

    def read_ushort_array(self, num: int) -> tuple:
        return self.read_uint16_array(num)

    def write_uint16(self, value: int) -> int:
        return self.stream_pack("H", value)

    def write_ushort(self, value: int) -> int:
        return self.write_uint16(value)

    def write_uint16_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "H", *values)

    def write_ushort_array(self, values: (list, tuple)) -> int:
        return self.write_uint16_array(values)

    # int32/int/long
    def read_int32(self) -> int:
        return self.stream_unpack("i")[0]

    def read_int(self) -> int:
        return self.read_int32()

    def read_long(self) -> int:
        return self.read_int32()

    def read_int32_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "i")

    def read_int_array(self, num: int) -> tuple:
        return self.read_int32_array(num)

    def read_long_array(self, num: int) -> tuple:
        return self.read_int32_array(num)

    def write_int32(self, value: int) -> int:
        return self.stream_pack("i", value)

    def write_int(self, value: int) -> int:
        return self.write_int32(value)

    def write_long(self, value: int) -> int:
        return self.write_int32(value)

    def write_int32_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "i", *values)

    def write_int_array(self, values: (list, tuple)) -> int:
        return self.write_int32_array(values)

    def write_long_array(self, values: (list, tuple)) -> int:
        return self.write_int32_array(values)

    # uint32/uint/ulong
    def read_uint32(self) -> int:
        return self.stream_unpack("I")[0]

    def read_uint(self) -> int:
        return self.read_uint32()

    def read_ulong(self) -> int:
        return self.read_uint32()

    def read_uint32_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "I")

    def read_uint_array(self, num: int) -> tuple:
        return self.read_uint32_array(num)

    def read_ulong_array(self, num: int) -> tuple:
        return self.read_uint32_array(num)

    def write_uint32(self, value: int) -> int:
        return self.stream_pack("I", value)

    def write_uint(self, value: int) -> int:
        return self.write_uint32(value)

    def write_ulong(self, value: int) -> int:
        return self.write_int32(value)

    def write_uint32_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "I", *values)

    def write_uint_array(self, values: (list, tuple)) -> int:
        return self.write_uint32_array(values)

    def write_ulong_array(self, values: (list, tuple)) -> int:
        return self.write_uint32_array(values)

    # int64/longlong
    def read_int64(self) -> int:
        return self.stream_unpack("q")[0]

    def read_longlong(self) -> int:
        return self.read_int64()

    def read_int64_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "q")

    def read_longlong_array(self, num: int) -> tuple:
        return self.read_int64_array(num)

    def write_int64(self, value: int) -> int:
        return self.stream_pack("q", value)

    def write_longlong(self, value: int) -> int:
        return self.write_int64(value)

    def write_int64_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "q", *values)

    def write_longlong_array(self, values: (list, tuple)) -> int:
        return self.write_int64_array(values)

    # uint64/ulonglong
    def read_uint64(self) -> int:
        return self.stream_unpack("Q")[0]

    def read_ulonglong(self) -> int:
        return self.read_uint64()

    def read_uint64_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "Q")

    def read_ulonglong_array(self, num: int) -> tuple:
        return self.read_uint64_array(num)

    def write_uint64(self, value: int) -> int:
        return self.stream_pack("Q", value)

    def write_ulonglong(self, value: int) -> int:
        return self.write_uint64(value)

    def write_uint64_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "Q", *values)

    def write_ulonglong_array(self, values: (list, tuple)) -> int:
        return self.write_uint64_array(values)

    # float32/single
    def read_float32(self) -> float:
        return self.stream_unpack("f")[0]

    def read_single(self) -> float:
        return self.read_float32()

    def read_float32_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "f")

    def read_single_array(self, num: int) -> tuple:
        return self.read_float32_array(num)

    def write_float32(self, value: float) -> float:
        return self.stream_pack("f", value)

    def write_single(self, value: float) -> float:
        return self.write_float32(value)

    def write_float32_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "f", *values)

    def write_single_array(self, values: (list, tuple)) -> int:
        return self.write_float32_array(values)

    # float64/double
    def read_float64(self) -> float:
        return self.stream_unpack("d")[0]

    def read_double(self) -> float:
        return self.read_float64()

    def read_float64_array(self, num: int) -> tuple:
        return self.stream_unpack(str(num) + "d")

    def read_double_array(self, num: int) -> tuple:
        return self.read_float64_array(num)

    def write_float64(self, value: float) -> float:
        return self.stream_pack("d", value)

    def write_double(self, value: float) -> float:
        return self.write_float64(value)

    def write_float64_array(self, values: (list, tuple)) -> int:
        return self.stream_pack(str(len(values)) + "d", *values)

    def write_double_array(self, values: (list, tuple)) -> int:
        return self.write_float64_array(values)

    # varint
    def read_varint(self) -> int:
        shift = 0
        result = 0
        while True:
            i = self.read_ubyte()
            result |= (i & 0x7f) << shift
            shift += 7
            if not (i & 0x80):
                break
        return result

    def read_varint_array(self, num: int) -> tuple:
        output = []
        for x in range(num):
            output.append(self.read_varint())
        return tuple(output)

    def write_varint(self, num: int) -> int:
        buff = b""
        while True:
            towrite = num & 0x7f
            num >>= 7
            if num:
                buff += bytes([(towrite | 0x80)])
            else:
                buff += bytes([towrite])
                break
        return self.write_ubytes(buff)

    def write_varint_array(self, values: (list, tuple)) -> tuple:
        output = []
        for single in values:
            output.append(self.write_varint(single))
        return tuple(output)

    # strings
    def read_int7(self) -> int:
        index = 0
        result = 0
        while True:
            byte_value = self.read_ubyte()
            result |= (byte_value & 0x7F) << (7 * index)
            if byte_value & 0x80 == 0:
                break
            index += 1
        return result

    def read_int7_array(self, num: int) -> tuple:
        output = []
        for x in range(num):
            output.append(self.read_int7())
        return tuple(output)

    def write_int7(self, value: int) -> int:
        data = b""
        num = value
        while num >= 0x80:
            data += bytes([((num | 0x80) & 0xFF)])
            num >>= 7
        data += bytes([num & 0xFF])
        return self.write(data)

    def write_int7_array(self, values: (list, tuple)) -> tuple:
        output = []
        for single in values:
            output.append(self.write_int7(single))
        return tuple(output)

    def read_string(self, encoding: str = "utf8") -> str:
        return self.read(self.read_int7()).decode(encoding)

    def read_c_string(self, encoding: str = "utf8") -> str:
        temp = None
        output = b""
        while temp != b"\x00":
            temp = self.read(1)
            output += temp
        return output.rstrip(b"\x00").decode(encoding)

    def read_str(self, encoding: str = "utf8") -> str:
        return self.read_string(encoding)

    def read_c_str(self, encoding: str = "utf8") -> str:
        return self.read_c_string(encoding)

    def write_string(self, value: str, encoding: str = "utf8") -> int:
        self.write_int7(len(value))
        return self.write(value.encode(encoding))

    def write_str(self, value: str, encoding: str = "utf8") -> int:
        return self.write_string(value, encoding)

    # hex
    def read_hex(self, num: int) -> (bytes, bytearray):
        return hexlify(self.read(num))

    def write_hex(self, value: str) -> int:
        return self.write(unhexlify(value))

    # hashing
    def read_section_md5(self, offset: int, sections: (list, tuple)) -> bool:
        loc = self.tell()
        hasher = md5()
        self.seek(offset)
        stored = self.read(MD5_DIGEST_LEN)
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(loc)
        return stored == hasher.digest()

    def read_section_sha1(self, offset: int, sections: (list, tuple)) -> bool:
        loc = self.tell()
        hasher = sha1()
        self.seek(offset)
        stored = self.read(SHA1_DIGEST_LEN)
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(loc)
        return stored == hasher.digest()

    def read_section_sha256(self, offset: int, sections: (list, tuple)) -> bool:
        loc = self.tell()
        hasher = sha256()
        self.seek(offset)
        stored = self.read(SHA256_DIGEST_LEN)
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(loc)
        return stored == hasher.digest()

    def read_section_sha512(self, offset: int, sections: (list, tuple)) -> bool:
        loc = self.tell()
        hasher = sha512()
        self.seek(offset)
        stored = self.read(SHA512_DIGEST_LEN)
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(loc)
        return stored == hasher.digest()

    def write_section_md5(self, offset: int, sections: (list, tuple)) -> None:
        loc = self.tell()
        hasher = md5()
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(offset)
        self.write(hasher.digest())
        self.seek(loc)

    def write_section_sha1(self, offset: int, sections: (list, tuple)) -> None:
        loc = self.tell()
        hasher = sha1()
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(offset)
        self.write(hasher.digest())
        self.seek(loc)

    def write_section_sha256(self, offset: int, sections: (list, tuple)) -> None:
        loc = self.tell()
        hasher = sha256()
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(offset)
        self.write(hasher.digest())
        self.seek(loc)

    def write_section_sha512(self, offset: int, sections: (list, tuple)) -> None:
        loc = self.tell()
        hasher = sha512()
        for single in sections:
            assert isinstance(single, StreamSection), "Sections must be of type StreamSection"
            self.seek(single.offset)
            hasher.update(self.read(single.size))
        self.seek(offset)
        self.write(hasher.digest())
        self.seek(loc)

    # structures/structs
    def read_struct(self, struct_type: (Structure, BigEndianStructure)) -> (Structure, BigEndianStructure):
        return struct_type.from_buffer_copy(self.read(sizeof(struct_type)))

    def read_struct_at(self, offset: int, struct_type: (Structure, BigEndianStructure)) -> (Structure, BigEndianStructure):
        loc = self.tell()
        self.seek(offset)
        output = self.read_struct(struct_type)
        self.seek(loc)
        return output

    def write_struct(self, struct_obj: (Structure, BigEndianStructure)) -> int:
        return self.write(bytes(struct_obj))

    def write_struct_at(self, offset: int, struct_obj: (Structure, BigEndianStructure)) -> int:
        loc = self.tell()
        self.seek(offset)
        output = self.write_struct(bytes(struct_obj))
        self.seek(loc)
        return output

    # functions
    def perform_function_at(self, offset: int, size: int, func):
        res = func(self.read_ubytes_at(offset, size))
        self.write_ubytes_at(offset, res)
        return res