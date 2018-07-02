# SigMaker-x64

IDA SigMaker Plugin updated for the IDA Pro 7.0 SDK by [dude719](https://github.com/dude719).

PLEASE NOTE: IDA Freeware 7.0 is **NOT** supported. 

Originally made by P4TR!CK

Credits also go to bobbysing and [xero|hawk](https://github.com/XeroHawk)

Thanks to [gir489](https://github.com/gir489) for the contributions

RIP GameDeception

# Installation

Visual Studio will expect the environment variable IDADIR to resolve to your IDA 7.0 installation directory.

Visual Studio will also expect the SDK to be located at %IDADIR%\idasdk. Make sure these folders resolve in Windows properly before attempting to build the project.

# Running the build

Because IDA no longer has a native 32-bit compiled version anymore, the Release/Debug scenarios are the build scripts for the 32-bit version of IDA and Release64/Debug64 are the build scripts for the 64-bit version.

**Do not change the target platform from x64!**
