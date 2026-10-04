// Probe-ProgId.js
// Usage: cscript.exe //nologo Probe-ProgId.js <ProgID>
// Only attempts COM activation. It does not invoke methods on the created object.

(function () {
    if (WScript.Arguments.length < 1) {
        WScript.Echo("ERROR|Missing ProgID");
        WScript.Quit(2);
    }

    var progId = WScript.Arguments(0);
    try {
        var obj = new ActiveXObject(progId);
        WScript.Echo("OK|" + progId);
        obj = null;
        WScript.Quit(0);
    } catch (e) {
        var n = (e.number >>> 0).toString(16).toUpperCase();
        WScript.Echo("FAIL|" + progId + "|0x" + n + "|" + (e.description || ""));
        WScript.Quit(1);
    }
})();
