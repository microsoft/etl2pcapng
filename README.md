
# About

This tool enables you to view ndiscap packet captures with Wireshark.

Windows ships with an inbox packet capture component called "ndiscap," which is implemented
as an ETW trace provider. Due to performance problems with the other popular packet capture
method (WinPcap, which was included with older versions of Wireshark), ndiscap should be
preferred. A capture can be collected with:

netsh trace start capture=yes report=disabled

netsh trace stop

The file generated by ndiscap is an etl file, which can be opened by ETW-centric tools
like Microsoft Message Analyzer, but cannot be opened by Wireshark, which is the preferred
tool for many engineers. Etl2pcapng.exe can convert the etl file to a pcapng file for
opening with Wireshark.

# Bluetooth

This tool can also convert Bluetooth captures. A capture can be collected with:

    logman create trace "bth_hci" -ow -o C:\bth_hci.etl -p {8a1f9517-3a8c-4a9e-a018-4f17a200f277} 0xffffffffffffffff 0xff -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets

    logman stop "bth_hci" -ets

# Usage

Prebuilt binaries are available in the Releases section: https://github.com/microsoft/etl2pcapng/releases

Run the tool with:

etl2pcapng.exe in.etl out.pcapng

After converting the file, the tool prints a table which shows mappings between Windows
interface indices and pcapng interface IDs.

The output pcapng file will have a comment on each packet indicating the PID
of the current process when the packet was logged. WARNING: this is frequently
not the same as the actual PID of the process which caused the packet to be
sent or to which the packet was delivered, since the packet capture provider
often runs in a DPC (which runs in an arbitrary process). The user should keep
this in mind when using the PID information.

# Building

Run in the src directory in a Visual Studio Command Prompt:

msbuild -t:rebuild -p:configuration=release -p:platform=win32

msbuild -t:rebuild -p:configuration=release -p:platform=x64

# History

1.4.0 - Automatically infer original fragment length if captured fragments were truncated.

1.3.0 - Add a comment to each packet containing the process id (PID).

1.2.0 - Write direction info of each packet (epb_flags)

1.1.0 - Added support for multi-event packets found in traces from Win8 and older

# Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
