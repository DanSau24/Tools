To trace COM+ registered components we can trace it this way:


There are ETW providers.
 
From an elevated cmd.exe.
 
To start:
 
reg add HKEY_LOCAL_MACHINE\Software\Microsoft\OLE\Tracing /v ExecutablesToTrace /t REG_MULTI_SZ /d * /f
 
logman start "NT Kernel Logger" -ow -o kernel.etl -p "Windows Kernel Trace" (process,thread) -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman start comsvcs -ow -o comsvcs.etl -p {B46FA1AD-B22D-4362-B072-9F5BA07B046D} 0xf 0x5 -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman start comadmin -ow -o comadmin.etl -p {A0C4702B-51F7-4ea9-9C74-E39952C694B8} 0xf 0x5 -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman start dcomscm -ow -o dcomscm.etl -p {9474a749-a98d-4f52-9f45-5b20247e4f01} 0x7 0x5 -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
logman start ole32 -ow -o ole32.etl -p {bda92ae8-9f11-4d49-ba1d-a4c2abca692e} 0xf 0x5 -nb 16 16 -bs 1024 -mode Circular -f bincirc -max 4096 -ets
 
To stop:
 
reg delete HKEY_LOCAL_MACHINE\Software\Microsoft\OLE\Tracing /v ExecutablesToTrace /f
 
logman stop "NT Kernel Logger" -ets
logman -stop comsvcs -ets
logman -stop comadmin -ets
logman -stop dcomscm -ets
logman -stop ole32 -ets
 
How long does it take for the issue to occur?   How quickly can they stop the traces?  Do they have enough disk spaces to accommodate 20GBs?  Adjust "-max 4096" based on the answers.
