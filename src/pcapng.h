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
#define PCAPNG_OPTIONCODE_COMMENT   1
#define PCAPNG_OPTIONCODE_EPB_FLAGS 2

#define PCAPNG_LINKTYPE_ETHERNET    1
#define PCAPNG_LINKTYPE_RAW         101
#define PCAPNG_LINKTYPE_IEEE802_11  105

#define PCAPNG_SECTION_HEADER_MAGIC 0x1a2b3c4d // for byte order detection

#include <pshpack1.h>
struct PCAPNG_BLOCK_HEAD {
    DWORD Type;
    DWORD Length;
};
struct PCAPNG_SECTION_HEADER_BODY {
    DWORD Magic; // endian detection (set this to PCAPNG_SECTION_HEADER_MAGIC)
    USHORT MajorVersion;
    USHORT MinorVersion;
    INT64 Length;
};
struct PCAPNG_INTERFACE_DESC_BODY {
    USHORT LinkType;
    USHORT Reserved;
    DWORD SnapLen;
};
struct PCAPNG_ENHANCED_PACKET_BODY {
    DWORD InterfaceId;
    DWORD TimeStampHigh;
    DWORD TimeStampLow;
    DWORD CapturedLength; // excludes padding
    DWORD PacketLength;   // excludes padding
    BYTE PacketData[0];   // padded to 4 bytes
};
struct PCAPNG_BLOCK_OPTION_ENDOFOPT {
    USHORT Code;   // PCAPNG_OPTIONCODE_ENDOFOPT
    USHORT Length; // 0
};
struct PCAPNG_BLOCK_OPTION_EPB_FLAGS {
    USHORT Code;   // PCAPNG_OPTIONCODE_EPB_FLAGS
    USHORT Length; // 4
    DWORD Value;
};
struct PCAPNG_BLOCK_OPTION_COMMENT {
    USHORT Code;         // PCAPNG_OPTIONCODE_COMMENT
    USHORT Length;
    CHAR   Comment[0];   // padded to 4 bytes
};
struct PCAPNG_BLOCK_TAIL {
    DWORD Length; // Same as PCAPNG_BLOCK_HEAD.Length, for easier backward processing.
};
#include <poppack.h>

inline int
PcapNgWriteSectionHeader(
    HANDLE File
)
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_HEAD Head;
    struct PCAPNG_SECTION_HEADER_BODY Body;
    struct PCAPNG_BLOCK_TAIL Tail;
    int TotalLength = sizeof(Head) + sizeof(Body) + sizeof(Tail);

    Head.Type = PCAPNG_BLOCKTYPE_SECTION_HEADER;
    Head.Length = TotalLength;
    if (!WriteFile(File, &Head, sizeof(Head), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }

    Body.Magic = PCAPNG_SECTION_HEADER_MAGIC;
    Body.MajorVersion = 1;
    Body.MinorVersion = 0;
    Body.Length = -1;
    if (!WriteFile(File, &Body, sizeof(Body), NULL, NULL)) {
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

inline int
PcapNgWriteInterfaceDesc(
    HANDLE File,
    short LinkType,
    long SnapLen
)
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_HEAD Head;
    struct PCAPNG_INTERFACE_DESC_BODY Body;
    struct PCAPNG_BLOCK_TAIL Tail;
    int TotalLength = sizeof(Head) + sizeof(Body) + sizeof(Tail);

    Head.Type = PCAPNG_BLOCKTYPE_INTERFACEDESC;
    Head.Length = TotalLength;
    if (!WriteFile(File, &Head, sizeof(Head), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }

    Body.LinkType = LinkType;
    Body.Reserved = 0;
    Body.SnapLen = SnapLen;
    if (!WriteFile(File, &Body, sizeof(Body), NULL, NULL)) {
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

inline int
PcapNgWriteCommentOption(
    __in HANDLE File,
    __in PCHAR CommentBuffer,
    __in USHORT CommentLength
)
{
    int Err = NO_ERROR;
    int CommentPadLength = 4 - (CommentLength % 4 == 0 ? 4 : CommentLength % 4);
    struct PCAPNG_BLOCK_OPTION_COMMENT Comment;
    char Pad[4] = { 0 };

    Comment.Code = PCAPNG_OPTIONCODE_COMMENT;
    Comment.Length = CommentLength;

    if (!WriteFile(File, &Comment, sizeof(Comment), NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }
    if (!WriteFile(File, CommentBuffer, CommentLength, NULL, NULL)) {
        Err = GetLastError();
        printf("WriteFile failed with %u\n", Err);
        goto Done;
    }
    if (CommentPadLength > 0) {
        if (!WriteFile(File, Pad, CommentPadLength, NULL, NULL)) {
            Err = GetLastError();
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }
    }

Done:

    return Err;
}

inline int
PcapNgWriteEnhancedPacket(
    HANDLE File,
    char* FragBuf,
    unsigned long FragLength,
    long InterfaceId,
    long IsSend,
    long TimeStampHigh, // usec (unless if_tsresol is used)
    long TimeStampLow,
    char* Comment,
    USHORT CommentLength
)
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_HEAD Head;
    struct PCAPNG_ENHANCED_PACKET_BODY Body;
    struct PCAPNG_BLOCK_OPTION_ENDOFOPT EndOption;
    struct PCAPNG_BLOCK_OPTION_EPB_FLAGS EpbFlagsOption;
    struct PCAPNG_BLOCK_TAIL Tail;
    char Pad[4] = {0};
    BOOLEAN commentprovided = (CommentLength > 0 && Comment != NULL);
    int FragPadLength = (4 - ((sizeof(Body) + FragLength) & 3)) & 3; // pad to 4 bytes per the spec.
    int TotalLength =
        sizeof(Head) + sizeof(Body) + FragLength + FragPadLength +
        sizeof(EpbFlagsOption) + sizeof(EndOption) + sizeof(Tail) +
        (commentprovided ?
            sizeof(struct PCAPNG_BLOCK_OPTION_COMMENT) + sizeof(EndOption) + CommentLength +
            (4 - (CommentLength % 4 == 0 ? 4 : CommentLength % 4)) //Comment Padding
            : 0);

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

    if (commentprovided)
    {
        Err = PcapNgWriteCommentOption(
            File,
            Comment,
            CommentLength
        );
        if (Err != NO_ERROR)
        {
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }
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
