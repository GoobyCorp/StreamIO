# StreamIO

This is a stream reader and writer written in Python 3 compatible with .NET's BinaryReader and BinaryWriter classes but with configurable endianness.

This library is able to write these data types:
* UInt8 / Int8 / byte
* UInt16 / Int16 / ushort / short
* UInt32 / Int32 / int / uint / long / ulong
* UInt64 / Int64 / longlong / ulonglong
* Float32 / float / single
* Float64 / double
* Google protobuf's varint
* C-style strings
* 7-bit int prepended strings (BinaryReader and BinaryWriter compatible!)
* ctypes structs (Structure and BigEndianStructure)