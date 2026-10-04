// Probe-ActCtx.js
// Usage: cscript.exe //nologo Probe-ActCtx.js <manifestPath> <ProgID>
// Uses Microsoft.Windows.ActCtx for registration-free COM activation.

(function () {
    if (WScript.Arguments.length < 2) {
        WScript.Echo("ERROR|Usage: Probe-ActCtx.js <manifestPath> <ProgID>");
        WScript.Quit(2);
    }

    var manifestPath = WScript.Arguments(0);
    var progId = WScript.Arguments(1);

    try {
        var act = new ActiveXObject("Microsoft.Windows.ActCtx");
        act.Manifest = manifestPath;
        var obj = act.CreateObject(progId);
        WScript.Echo("OK|ACTCTX|" + progId + "|" + manifestPath);
        obj = null;
        act = null;
        WScript.Quit(0);
    } catch (e) {
        var n = (e.number >>> 0).toString(16).toUpperCase();
        WScript.Echo("FAIL|ACTCTX|" + progId + "|0x" + n + "|" + (e.description || ""));
        WScript.Quit(1);
    }
})();
