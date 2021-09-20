# volatility-bitlocker

**Update 2016-04-06:** Applied a hacky fix for 32-bit windows. I've realised that I need a more robust solution to handle slight differences in Windows 8 and 32-bit Windows... That will happen soon and will include full Windows 8 support. Until then, Win8 is not currently supported ( 8.1 is though). Contact me if you need more info.

A plugin for the Volatility Framework which aims to extract BitLocker Full Volume Encryption Keys (FVEK) from memory. Works on Windows 7 through to Windows 10.

This is very much a work-in-progress and support for Windows 8 - 10 is highly experimental.

Finds the FVEK on Windows 7 by searching for the FVEc pool tag.

Attempts to locate the FVEK on Windows 8, 8.1 and 10 by analysing memory after finding the Cngb pool tag.

Article here: https://tribalchicken.net/recovering-bitlocker-keys-on-windows-8-1-and-10/

## Usage
bitlocker.py is a plugin for the Volatility Framework. You can either place the plugin in the plugins directory at `volatility/plugins`, or  alternatively, you can place the plugin in a separate directory and point volatility to it with `--plugins`

For example, using a directory called "Plugins":

```
voldev$ ls plugins
bitlocker.py
voldev$ volatility --plugins=plugins/ --profile=Win81U1x64 -f WIN81X64-20160916-061911.raw bitlocker
```

## Common Problems

### Volatility tells you it needs something to do

Volatility doesn't know about the plugin. Check the location of the plugin, and run `volatility --info` to determine if it is detected

### The plugin doesn't find anything
There could be many causes.

- The drive is not bitlocker encrypted
- The memory image does not contain the key (Image captured after key is evicted from memory, overwritten during acquisition, etc)
- The key exists but the plugin doesn't find it.

If you suspect the plugin isn't working for you then I would love to know.

