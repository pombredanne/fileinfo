# fileinfo

This program displays information of Windows PE files.

Add this program to Windows Explorer right click menu for easy use, by setting these registry keys:
  `HKCR\dllfile\shell\Check Info\command: (default) [exe path] "%1" [option]`  
  `HKCR\exefile\shell\Check Info\command: (default) [exe path] "%1" [option]`  
  `HKCR\sysfile\shell\Check Info\command: (default) [exe path] "%1" [option]`  

Usage: `QuickFileInfo.exe [file path] [--proxy=domain:port] [--dark | --light]`  
  `--proxy`: The proxy server to use to download PDB symbols from Microsoft. You can specify `--proxy=direct` to never use a proxy, and `--proxy=system` to use the system proxy.  
  `--dark` | `--light`: Enable or disable dark mode. If not set, the system default theme is used.  

Information shown by this program:
1. 64-bit vs 32-bit
2. Image characteristics
3. MD5, SHA1, SHA256
4. Debug GUID
5. Many more ...
