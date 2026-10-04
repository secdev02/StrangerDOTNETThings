# TLB Research Kit v1.0.0

A Windows PowerShell 5.1 research kit for loading COM type libraries (`.tlb`), enumerating their coclasses/interfaces/members, attempting COM activation, and optionally invoking conservative zero-argument methods.

It uses only built-in Windows / .NET Framework functionality:

- Windows PowerShell 5.1
- `Add-Type`
- `oleaut32.dll!LoadTypeLibEx`
- `.NET Framework` `System.Runtime.InteropServices.ComTypes`
- `System.Type.GetTypeFromCLSID()`
- `System.Activator`

No Visual Studio, NuGet packages, or external PowerShell modules are required.

## Important concept

A `.tlb` is **metadata**, not executable implementation.

For example:

```text
SimpleMessage.tlb
    |
    +-- IHelloMessage
    |     +-- Name
    |     +-- Message
    |     +-- ShowMessage()
    |
    +-- SimpleMessage coclass
          +-- CLSID
```

The method body that actually shows a message box lives in the implementation DLL/EXE:

```text
SimpleMessage.dll
    |
    +-- ShowMessage()
          |
          +-- MessageBox.Show(...)
```

`LoadTypeLibEx()` can load and inspect the metadata, but COM activation still requires a registered or otherwise activatable COM implementation.

---

# Files

```text
README.md
New-SampleTypeLib.ps1
Inspect-Tlb.ps1
Invoke-TlbResearch.ps1
Test-Sample.ps1
```

## `New-SampleTypeLib.ps1`

Creates a known-safe sample COM-visible .NET Framework assembly and exports:

```text
Sample\
    SimpleMessage.dll
    SimpleMessage.tlb
```

The object exposes:

```text
Name        property
Message     property
ShowMessage() method
```

`ShowMessage()` displays a Windows message box.

The script also optionally registers the assembly for COM with the .NET Framework `RegAsm.exe`.

## `Inspect-Tlb.ps1`

Loads a `.tlb` with:

```text
oleaut32.dll!LoadTypeLibEx(..., REGKIND_NONE, ...)
```

and returns structured PowerShell objects describing:

- Type library name
- Type library GUID
- Version
- LCID
- Type kind
- Coclass CLSIDs
- Interfaces
- Methods
- Property getters/setters
- DISPIDs / MEMIDs
- Parameter counts
- VTable offsets
- Type flags

It can export JSON and CSV.

## `Invoke-TlbResearch.ps1`

Builds on `Inspect-Tlb.ps1`.

For each coclass it:

1. Extracts the CLSID.
2. Looks for a registered ProgID.
3. Tries `Type.GetTypeFromCLSID()`.
4. Attempts `Activator.CreateInstance()`.
5. Records whether activation succeeded.
6. Enumerates members described by the TLB.
7. Optionally invokes conservative zero-argument methods.

By default, it **does not call methods**.

To allow zero-argument method calls, supply:

```powershell
-InvokeSafeZeroArg
```

The script skips method names containing high-risk verbs such as:

```text
Delete
Remove
Kill
Terminate
Shutdown
Restart
Execute
Run
ShellExecute
Open
Navigate
Send
Write
Save
Create
Add
Update
Commit
Apply
Connect
Disconnect
```

This denylist is intentionally conservative and is not a security boundary. Only use invocation mode on objects you understand and in a disposable/test environment.

---

# Quick start

Open **Windows PowerShell 5.1**:

```powershell
powershell.exe
```

Create the sample:

```powershell
.\New-SampleTypeLib.ps1
```

Inspect the generated TLB:

```powershell
.\Inspect-Tlb.ps1 `
    -Path .\Sample\SimpleMessage.tlb
```

Export results:

```powershell
.\Inspect-Tlb.ps1 `
    -Path .\Sample\SimpleMessage.tlb `
    -JsonPath .\sample.json `
    -CsvPath .\sample-members.csv
```

Try activation:

```powershell
.\Invoke-TlbResearch.ps1 `
    -Path .\Sample\SimpleMessage.tlb
```

If you generated the sample with COM registration enabled:

```powershell
.\New-SampleTypeLib.ps1 -Register
```

you can test its safe zero-argument method:

```powershell
.\Invoke-TlbResearch.ps1 `
    -Path .\Sample\SimpleMessage.tlb `
    -InvokeSafeZeroArg
```

For the sample object this should call:

```text
ShowMessage()
```

and display the message box.

---

# Direct COM usage of the sample

After registration:

```powershell
$o = New-Object -ComObject DemoTypeLib.SimpleMessage

$o.Name = "PowerShell"
$o.Message = "Hello from COM"

$o.ShowMessage()
```

Or by CLSID:

```powershell
$clsid = [guid]"{17C23391-C543-4A11-88D1-675C652250D1}"

$type = [type]::GetTypeFromCLSID($clsid, $true)
$o = [Activator]::CreateInstance($type)

$o.Name = "CLSID activation"
$o.Message = "Activated from the class ID."

$o.ShowMessage()
```

---

# Loading the TLB itself

The relevant built-in Windows API is:

```text
oleaut32.dll!LoadTypeLibEx
```

not `ole32.dll`.

The script uses:

```text
REGKIND_NONE
```

which tells Windows to load the type library without registering it.

Conceptually:

```powershell
$tlb = LoadTypeLibEx("Example.tlb", REGKIND_NONE)
```

returns an `ITypeLib`.

From it, the script walks:

```text
ITypeLib
  |
  +-- ITypeInfo
        |
        +-- TYPEATTR
        +-- FUNCDESC
        +-- VARDESC
        +-- documentation / names
```

---

# Inspecting arbitrary installed TLBs

Example:

```powershell
.\Inspect-Tlb.ps1 -Path C:\Path\To\Something.tlb
```

You can filter only coclasses:

```powershell
$r = .\Inspect-Tlb.ps1 -Path C:\Path\To\Something.tlb

$r.Types |
    Where-Object TypeKind -eq 'TKIND_COCLASS' |
    Format-Table Name, Guid
```

Find zero-argument methods:

```powershell
$r.Types.Members |
    Where-Object {
        $_.InvokeKind -eq 'INVOKE_FUNC' -and
        $_.ParameterCount -eq 0
    } |
    Format-Table TypeName, Name, MemId
```

---

# Activation behavior

A TLB can describe a coclass whose implementation is not currently activatable.

Common reasons include:

- class not registered
- 32-bit / 64-bit mismatch
- missing implementation DLL
- local server not installed
- registration-free COM manifest required
- activation context required
- class factory refuses the requested context
- server-specific initialization requirements

Therefore:

```text
TLB present
```

does **not** imply:

```text
COM class can be instantiated
```

`Invoke-TlbResearch.ps1` records activation failures instead of treating them as parser failures.

---

# 32-bit vs 64-bit

COM registration can be bitness-specific.

64-bit Windows PowerShell:

```text
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

32-bit Windows PowerShell:

```text
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
```

The sample registration script automatically chooses the matching .NET Framework `RegAsm.exe` for the current PowerShell process.

If a coclass exists only in the 32-bit COM registry view, inspect/activate it from 32-bit PowerShell.

---

# Safety model

The toolkit separates three operations:

```text
Inspection
    read TLB metadata only

Activation
    create a COM object

Invocation
    actually call methods
```

`Inspect-Tlb.ps1` performs only the first operation.

`Invoke-TlbResearch.ps1` performs inspection and activation by default.

Method calls require the explicit switch:

```powershell
-InvokeSafeZeroArg
```

Even then, the built-in filtering is heuristic. A zero-argument method can still have side effects.

Use invocation mode only on software you trust and preferably inside a test VM.

---

# Microsoft APIs used

The implementation relies on standard Windows COM Automation APIs and .NET Framework COM interop types:

```text
LoadTypeLibEx
ITypeLib
ITypeInfo
TYPEATTR
FUNCDESC
System.Type.GetTypeFromCLSID
System.Activator.CreateInstance
```

`LoadTypeLibEx(..., REGKIND_NONE, ...)` loads the library without registering it.

---

# Useful research ideas

This kit can help answer questions such as:

```text
Which coclasses are described by this TLB?

Which CLSIDs are present?

Which coclasses are registered on this machine?

Which classes can actually be activated by this user?

Which methods/properties are described by ITypeInfo?

Which methods take zero parameters?

Which interfaces are implemented by each coclass?

Does 32-bit activation differ from 64-bit activation?

Which installed COM servers expose interesting automation interfaces?
```

For broad machine-wide COM research, keep **enumeration**, **activation**, and **invocation** as separate phases. That makes results reproducible and prevents an inspection pass from accidentally changing machine state.
