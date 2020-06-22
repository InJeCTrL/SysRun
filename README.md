# SysRun

> Execute programs as system privilege

## Usage

```
sysrun.exe FILEPATH
```

## API call flow

| API | Goal |
| --- | --- |
| RtlAdjustPrivilege | switch process to debug privilege |
| EnumProcesses & GetProcessImageFileName | lookup pid by process name(winlogon.exe) |
| OpenProcess | get process handle of winlogon |
| OpenProcessToken | get privilege token |
| DuplicateTokenEx | get duplicated privilege token |
| CreateProcessWithTokenW | execute program with high privilege same as winlogon by using privilege token |