# fileinfo

This program displays information of Windows PE files.

Add this program to Windows Explorer right click menu for easy use, by setting these registry keys:
  `HKCR\dllfile\shell\Check Info\command: (default) [exe path] "%1" [option]`  
  `HKCR\exefile\shell\Check Info\command: (default) [exe path] "%1" [option]`  
  `HKCR\sysfile\shell\Check Info\command: (default) [exe path] "%1" [option]`  

Usage: QuickFileInfo.exe [file path] [--proxy=domain:port] [--dark | --light] ["--run1=[path of external exe]|[parameters to external exe]|[button name]|[admin]"]
 * `--proxy`: The proxy server to use to download PDB symbols from Microsoft. You can specify `--proxy=direct` to never use a proxy, and `--proxy=system` to use the system proxy.  
 * `--dark` | `--light`: Enable or disable dark mode. If not set, the system default theme is used.  
 * `--run1`: Add an additional button. Clicking it opens the specified external program.   
      [path of external exe]: The full path of the external program. Don't quote it if it contains space; instead, quote the entire --run1 parameter.   
      [parameters to external exe]: The parameters to the external program. %1 refers to [file path]. Note that quotes inside this sub-parameter MUST be escaped as \\".   
      [button name]: The text shown on this button.   
      [admin]: Specify the string "admin" (without quotes) to launch the external program as administrator; otherwise it will be launched unelevated.   

 
Information shown by this program:
1. 64-bit vs 32-bit
2. Image characteristics
3. MD5, SHA1, SHA256
4. Debug GUID
5. Many more ...
