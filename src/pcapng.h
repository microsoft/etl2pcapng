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

#define PCAPNG_OPTIONCODE_IDB_IF_NAME 2
#define PCAPNG_OPTIONCODE_IDB_IF_DESC 3

#define PCAPNG_LINKTYPE_ETHERNET    1
#define PCAPNG_LINKTYPE_RAW         101
#define PCAPNG_LINKTYPE_IEEE802_11  105

#define PCAPNG_SECTION_HEADER_MAGIC 0x1a2b3c4d // for byte order detection

#define PAD_TO_32BIT(x) ((4 - ((x) & 3)) & 3)

#include <pshpack1.h>
struct PCAPNG_BLOCK_HEAD {
    unsigned long Type;
    unsigned long Length;
};
struct PCAPNG_SECTION_HEADER_BODY {
    unsigned long  Magic; // endian detection (set this to PCAPNG_SECTION_HEADER_MAGIC)
    unsigned short MajorVersion;
    unsigned short MinorVersion;
    long long      Length;
};
struct PCAPNG_INTERFACE_DESC_BODY {
    unsigned short LinkType;
    unsigned short Reserved;
    unsigned long  SnapLen;
};
struct PCAPNG_ENHANCED_PACKET_BODY {
    unsigned long InterfaceId;
    unsigned long TimeStampHigh;
    unsigned long TimeStampLow;
    unsigned long CapturedLength; // excludes padding
    unsigned long PacketLength;   // excludes padding
    unsigned char PacketData[0];  // padded to 4 bytes
};
struct PCAPNG_BLOCK_OPTION_ENDOFOPT {
    unsigned short Code;          // PCAPNG_OPTIONCODE_ENDOFOPT
    unsigned short Length;        // 0
};
struct PCAPNG_BLOCK_OPTION_EPB_FLAGS {
    unsigned short Code;          // PCAPNG_OPTIONCODE_EPB_FLAGS
    unsigned short Length;        // 4
    unsigned long  Value;
};
struct PCAPNG_BLOCK_OPTION_STRING {
    unsigned short Code;          // PCAPNG_OPTIONCODE_COMMENT
    unsigned short Length;
    char           Comment[0];    // padded to 4 bytes
};
struct PCAPNG_BLOCK_TAIL {
    unsigned long Length;         // Same as PCAPNG_BLOCK_HEAD.Length, for easier backward processing.
};
#include <poppack.h>

struct PCAPNG_BLOCK_OPTION_ENDOFOPT EndOption = { .Code = PCAPNG_OPTIONCODE_ENDOFOPT, .Length = 0};

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
    long SnapLen,
    char* IfName,
    unsigned short IfNameLength,
    char* IfDesc,
    unsigned short IfDescLength
    )
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_HEAD Head;
    struct PCAPNG_INTERFACE_DESC_BODY Body;
    struct PCAPNG_BLOCK_TAIL Tail;
    struct PCAPNG_BLOCK_OPTION_STRING IfNameOpt;
    struct PCAPNG_BLOCK_OPTION_STRING IfDescOpt;
    char Pad[4] = { 0 };

    int TotalLength = sizeof(Head) + sizeof(Body) + sizeof(Tail);

    if (IfName != NULL) {
        IfNameOpt.Code = PCAPNG_OPTIONCODE_IDB_IF_NAME;
        IfNameOpt.Length = IfNameLength;
        TotalLength += sizeof(IfNameOpt) + IfNameLength + PAD_TO_32BIT(IfNameLength);
    }

    if (IfDesc != NULL) {
        IfDescOpt.Code = PCAPNG_OPTIONCODE_IDB_IF_DESC;
        IfDescOpt.Length = IfDescLength;
        TotalLength += sizeof(IfDescOpt) + IfDescLength + PAD_TO_32BIT(IfDescLength);
    }

    if (IfName != NULL || IfDesc != NULL) {
        TotalLength += sizeof(EndOption);
    }

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

    if (IfName != NULL) {
        if (!WriteFile(File, &IfNameOpt, sizeof(IfNameOpt), NULL, NULL)) {
            Err = GetLastError();
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }

        if (!WriteFile(File, IfName, IfNameLength, NULL, NULL)) {
            Err = GetLastError();
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }

        if (PAD_TO_32BIT(IfNameLength) > 0) {
            if (!WriteFile(File, Pad, PAD_TO_32BIT(IfNameLength), NULL, NULL)) {
                Err = GetLastError();
                printf("WriteFile failed with %u\n", Err);
                goto Done;
            }
        }
    }

    if (IfDesc != NULL) {
        if (!WriteFile(File, &IfDescOpt, sizeof(IfDescOpt), NULL, NULL)) {
            Err = GetLastError();
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }

        if (!WriteFile(File, IfDesc, IfDescLength, NULL, NULL)) {
            Err = GetLastError();
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }

        if (PAD_TO_32BIT(IfDescLength) > 0) {
            if (!WriteFile(File, Pad, PAD_TO_32BIT(IfDescLength), NULL, NULL)) {
                Err = GetLastError();
                printf("WriteFile failed with %u\n", Err);
                goto Done;
            }
        }
    }

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

inline int
PcapNgWriteCommentOption(
    HANDLE File,
    PCHAR CommentBuffer,
    unsigned short CommentLength,
    int CommentPadLength
    )
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_OPTION_STRING Comment;
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
    unsigned long OrigFragLength,
    long InterfaceId,
    long IsSend,
    long TimeStampHigh, // usec (unless if_tsresol is used)
    long TimeStampLow,
    char* Comment,
    unsigned short CommentLength
    )
{
    int Err = NO_ERROR;
    struct PCAPNG_BLOCK_HEAD Head;
    struct PCAPNG_ENHANCED_PACKET_BODY Body;
    struct PCAPNG_BLOCK_OPTION_EPB_FLAGS EpbFlagsOption;
    struct PCAPNG_BLOCK_TAIL Tail;
    char Pad[4] = {0};
    BOOLEAN CommentProvided = (CommentLength > 0 && Comment != NULL);
    int CommentPadLength = (4 - (CommentLength & 3)) & 3; // pad to 4 bytes per the spec.
    int FragPadLength = (4 - ((sizeof(Body) + FragLength) & 3)) & 3;
    int TotalLength =
        sizeof(Head) + sizeof(Body) + FragLength + FragPadLength +
        sizeof(EpbFlagsOption) + sizeof(EndOption) + sizeof(Tail) +
        (CommentProvided ?
            sizeof(struct PCAPNG_BLOCK_OPTION_STRING) + CommentLength + CommentPadLength : 0);

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
    Body.PacketLength = OrigFragLength; // original length
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

    if (CommentProvided) {
        Err = PcapNgWriteCommentOption(
            File,
            Comment,
            CommentLength,
            CommentPadLength);
        if (Err != NO_ERROR) {
            printf("WriteFile failed with %u\n", Err);
            goto Done;
        }
    }

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
