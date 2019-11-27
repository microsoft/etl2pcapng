/*

Copyright (c) Microsoft Corporation.
Licensed under the MIT License.

Helpers for working with .pcapng files.
https://github.com/pcapng/pcapng

*/

#pragma once
#pragma warning(disable:4200) // zero-sized array

#define PCAPNG_BLOCKTYPE_SECTION_HEADER  0x0a0d0d0a
#define PCAPNG_BLOCKTYPE_INTERFACEDESC   0x00000001
#define PCAPNG_BLOCKTYPE_ENHANCED_PACKET 0x00000006

#define PCAPNG_OPTIONCODE_ENDOFOPT  0
#define PCAPNG_OPTIONCODE_EPB_FLAGS 2

#define PCAPNG_LINKTYPE_ETHERNET    1
#define PCAPNG_LINKTYPE_RAW         101
#define PCAPNG_LINKTYPE_IEEE802_11  105

#define PCAPNG_SECTION_HEADER_MAGIC 0x1a2b3c4d // for byte order detection

#include <pshpack1.h>
struct PCAPNG_BLOCK_HEAD {
    long Type;
    long Length;
};
struct PCAPNG_SECTION_HEADER_BODY {
    long Magic; // endian detection (set this to PCAPNG_SECTION_HEADER_MAGIC)
    short MajorVersion;
    short MinorVersion;
    long long Length;
};
struct PCAPNG_INTERFACE_DESC_BODY {
    short LinkType;
    short Reserved;
    long SnapLen;
};
struct PCAPNG_ENHANCED_PACKET_BODY {
    long InterfaceId;
    long TimeStampHigh;
    long TimeStampLow;
    long CapturedLength; // excludes padding
    long PacketLength; // excludes padding
    char PacketData[0]; // padded to 4 bytes
};
struct PCAPNG_BLOCK_OPTION_ENDOFOPT {
    short Code; // PCAPNG_OPTIONCODE_ENDOFOPT
    short Length; // 0
};
struct PCAPNG_BLOCK_OPTION_EPB_FLAGS {
    short Code; // PCAPNG_OPTIONCODE_EPB_FLAGS
    short Length; // 4
    long Value;
};
struct PCAPNG_BLOCK_TAIL {
    long Length; // Same as PCAPNG_BLOCK_HEAD.Length, for easier backward processing.
};
#include <poppack.h>

inline int
PcapNgWriteBlock(
    HANDLE File,
    int BlockType,
    char* Body,
    int BodyLength
    )
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_HEAD Head;
    struct PCAPNG_BLOCK_TAIL Tail;

    Head.Type = BlockType;

    Head.Length = Tail.Length = sizeof(Head) + BodyLength + sizeof(Tail);

    if (!WriteFile(File, &Head, sizeof(Head), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }
    if (!WriteFile(File, Body, BodyLength, NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }
    if (!WriteFile(File, &Tail, sizeof(Tail), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }
Done:
    return Err;
}

inline int
PcapNgWriteSectionHeader(
    HANDLE File
    )
{
    struct PCAPNG_SECTION_HEADER_BODY Body;
    Body.Magic = PCAPNG_SECTION_HEADER_MAGIC;
    Body.MajorVersion = 1;
    Body.MinorVersion = 0;
    Body.Length = -1;
    return PcapNgWriteBlock(File, PCAPNG_BLOCKTYPE_SECTION_HEADER, (char*)&Body, sizeof(Body));
}

inline int
PcapNgWriteInterfaceDesc(
    HANDLE File,
    short LinkType,
    long SnapLen
    )
{
    struct PCAPNG_INTERFACE_DESC_BODY Body;
    Body.LinkType = LinkType;
    Body.Reserved = 0;
    Body.SnapLen = SnapLen;
    return PcapNgWriteBlock(File, PCAPNG_BLOCKTYPE_INTERFACEDESC, (char*)&Body, sizeof(Body));
}

inline int
PcapNgWriteEnhancedPacket(
    HANDLE File,
    char* FragBuf,
    unsigned long FragLength,
    long InterfaceId,
    long IsSend,
    long TimeStampHigh, // usec (unless if_tsresol is used)
    long TimeStampLow
    )
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_HEAD Head;
    struct PCAPNG_ENHANCED_PACKET_BODY Body;
    struct PCAPNG_BLOCK_OPTION_ENDOFOPT EndOption;
    struct PCAPNG_BLOCK_OPTION_EPB_FLAGS EpbFlagsOption;
    struct PCAPNG_BLOCK_TAIL Tail;
    char Pad[4] = {0};
    int FragPadLength = (4 - ((sizeof(Body) + FragLength) & 3)) & 3; // pad to 4 bytes per the spec.

    int TotalLength = sizeof(Head) + sizeof(Body) + FragLength + FragPadLength + sizeof(Tail);

    Head.Type = PCAPNG_BLOCKTYPE_ENHANCED_PACKET;
    Head.Length = TotalLength;
    if (!WriteFile(File, &Head, sizeof(Head), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }

    Body.InterfaceId = InterfaceId;
    Body.TimeStampHigh = TimeStampHigh;
    Body.TimeStampLow = TimeStampLow;
    Body.PacketLength = FragLength; // actual length
    Body.CapturedLength = FragLength; // truncated length
    if (!WriteFile(File, &Body, sizeof(Body), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }
    if (!WriteFile(File, FragBuf, FragLength, NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }
    if (FragPadLength > 0) {
        if (!WriteFile(File, Pad, FragPadLength, NULL, NULL)) {
            Err = GetLastError();
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }
    }

    EpbFlagsOption.Code = PCAPNG_OPTIONCODE_EPB_FLAGS;
    EpbFlagsOption.Length = 4;
    EpbFlagsOption.Value = IsSend ? 2 : 1;
    if (!WriteFile(File, &EpbFlagsOption, sizeof(EpbFlagsOption), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }

    EndOption.Code = PCAPNG_OPTIONCODE_ENDOFOPT;
    EndOption.Length = 0;
    if (!WriteFile(File, &EndOption, sizeof(EndOption), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }

    Tail.Length = TotalLength;
    if (!WriteFile(File, &Tail, sizeof(Tail), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }

Done:
    return Err;
}
