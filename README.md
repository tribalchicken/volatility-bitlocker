# volatility-bitlocker

**Update 2016-04-06:** Applied a hacky fix for 32-bit windows. I've realised that I need a more robust solution to handle slight differences in Windows 8 and 32-bit Windows... That will happen soon and will include full Windows 8 support. Until then, Win8 is not currently supported ( 8.1 is though). Contact me if you need more info.

A plugin for the Volatility Framework which aims to extract BitLocker Full Volume Encryption Keys (FVEK) from memory. Works on Windows 7 through to Windows 10.

This is very much a work-in-progress and support for Windows 8 - 10 is highly experimental.

Finds the FVEK on Windows 7 by searching for the FVEc pool tag.

Attempts to locate the FVEK on Windows 8, 8.1 and 10 by analysing memory after finding the Cngb pool tag.

Article here: https://tribalchicken.com.au/technical/recovering-bitlocker-keys-on-windows-8-1-and-10/
