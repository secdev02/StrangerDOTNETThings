// x509com.js
// Enumerates the registered X509* COM classes (CertEnroll), prints the
// prototype of each known method/property, and calls the safe ones.
//
// Usage (run from a normal prompt, no admin needed):
//   cscript //nologo x509com.js              enumerate + prototypes + call safe members
//   cscript //nologo x509com.js /list        only enumerate registered X509* ProgIDs
//   cscript //nologo x509com.js /protos      enumerate + print prototypes, call nothing
//   cscript //nologo x509com.js /unsafe      also run members that touch the key store
//                                            (creates a temp key container, then deletes it)
//   cscript //nologo x509com.js /out:report.txt   choose the report file name
//
// Members that change real state (Enroll, InstallResponse, CreatePFX, Enrollment.Delete)
// are NEVER called, only listed.
//
// Note: WSH JScript cannot read COM type libraries, so the prototype catalog below is
// built in. Classes found in the registry but missing from the catalog are still listed
// and test-instantiated, just without prototypes.

var fso   = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");
var named = WScript.Arguments.Named;

var MODE   = named.Exists("list") ? "list" : (named.Exists("protos") ? "protos" : "call");
var UNSAFE = named.Exists("unsafe");
var OUTFILE = named.Exists("out") ? String(named.Item("out")) : "x509com-report.txt";

var report = [];
function out(s) {
    if (s === undefined) { s = ""; }
    WScript.Echo(s);
    report.push(s);
}

function pad(s, n) {
    s = String(s);
    while (s.length < n) { s += " "; }
    return s;
}

function fmt(v) {
    if (v === undefined) { return "(void)"; }
    if (v === null) { return "null"; }
    if (typeof v === "object") { return "[object]"; }
    var s = String(v);
    if (s.length > 60) { s = s.substring(0, 57) + "..."; }
    return s;
}

function hex(n) {
    return "0x" + (n >>> 0).toString(16).toUpperCase();
}

// ---------------------------------------------------------------------------
// Helpers used by the catalog
// ---------------------------------------------------------------------------
var PREFIX = "X509Enrollment.";
function mk(cls) { return new ActiveXObject(PREFIX + cls); }

var X = {
    oid: function (v) {
        var o = mk("CObjectId");
        o.InitializeFromValue(v || "1.3.6.1.5.5.7.3.1");
        return o;
    },
    oids: function () {
        var s = mk("CObjectIds");
        s.Add(X.oid());
        return s;
    },
    dn: function () {
        var d = mk("CX500DistinguishedName");
        d.Encode("CN=ProbeTest", 0);
        return d;
    },
    altName: function () {
        var a = mk("CAlternativeName");
        a.InitializeFromString(3, "localhost");   // 3 = DNS name
        return a;
    },
    altNames: function () {
        var n = mk("CAlternativeNames");
        n.Add(X.altName());
        return n;
    },
    ext: function () {
        var e = mk("CX509Extension");
        e.Initialize(X.oid("2.5.29.19"), 1, "MAMBAf8=");   // basicConstraints, CA:TRUE
        return e;
    }
};

function M(proto, fn, flag) { return { proto: proto, fn: fn, flag: flag || "" }; }

// Property helper: yields a getter and a setter entry
function P(type, name, val) {
    return [
        M(type + " get_" + name + "()", function (o) { return o[name]; }),
        M("void put_" + name + "(" + type + ")", function (o) { o[name] = val; return "set"; })
    ];
}

function skip(why) { throw { skip: why }; }
function need(st) {
    if (!st || !st.key) { skip("needs /unsafe (creates then deletes a temporary key)"); }
}

// Members every extension class inherits from IX509Extension
function extBase(own) {
    return own.concat([
        M("IObjectId get_ObjectId()", function (o) { return o.ObjectId.Value; }),
        M("BSTR get_RawData([in] EncodingType Encoding)", function (o) { return "len=" + String(o.RawData(1)).length; }),
        M("VARIANT_BOOL get_Critical()", function (o) { return o.Critical; }),
        M("void put_Critical(VARIANT_BOOL)", function (o) { o.Critical = true; return o.Critical; })
    ]);
}

// Temporary key used by the request/certificate classes (only with /unsafe)
function makeTempKey() {
    var k = mk("CX509PrivateKey");
    k.ProviderName   = "Microsoft Enhanced RSA and AES Cryptographic Provider";
    k.ProviderType   = 24;
    k.KeySpec        = 1;
    k.Length         = 2048;
    k.MachineContext = false;
    k.ContainerName  = "X509ComProbe" + (new Date()).getTime();
    k.Create();
    return k;
}
function dropTempKey(st) {
    if (st && st.key) { try { st.key.Delete(); } catch (e) {} }
}

// ---------------------------------------------------------------------------
// Catalog: ProgID suffix, interface name, setup/teardown, ordered members
// ---------------------------------------------------------------------------
var CATALOG = [];
function C(prog, iface, members, setup, teardown) {
    CATALOG.push({ prog: PREFIX + prog, iface: iface, members: members, setup: setup, teardown: teardown });
}

C("CObjectId", "IObjectId", [
    M("void InitializeFromName([in] CERTENROLL_OBJECTID Name)", function (o) { o.InitializeFromName(1); }),
    M("void InitializeFromValue([in] BSTR strValue)", function (o) { o.InitializeFromValue("1.3.6.1.5.5.7.3.1"); }),
    M("void InitializeFromAlgorithmName([in] ObjectIdGroupId GroupId, [in] ObjectIdPublicKeyFlags KeyFlags, [in] AlgorithmFlags AlgFlags, [in] BSTR strAlgorithmName)",
      function (o) { o.InitializeFromAlgorithmName(3, 0, 0, "SHA256"); }),
    M("BSTR get_Name()", function (o) { return o.Name; }),
    M("BSTR get_FriendlyName()", function (o) { return o.FriendlyName; }),
    M("void put_FriendlyName([in] BSTR)", function (o) { o.FriendlyName = "Probe"; return "set"; }),
    M("BSTR get_Value()", function (o) { return o.Value; }),
    M("BSTR GetAlgorithmName([in] ObjectIdGroupId GroupId, [in] ObjectIdPublicKeyFlags KeyFlags)",
      function (o) { return o.GetAlgorithmName(3, 0); })
]);

C("CObjectIds", "IObjectIds", [
    M("void Add([in] IObjectId pVal)", function (o, st) { st.oid = X.oid(); o.Add(st.oid); }),
    M("long get_Count()", function (o) { return o.Count; }),
    M("IObjectId get_ItemByIndex([in] long Index)", function (o) { return o.ItemByIndex(0).Value; }),
    M("long get_IndexByObjectId([in] IObjectId pObjectId)", function (o, st) { return o.IndexByObjectId(st.oid); }),
    M("void AddRange([in] IObjectIds pValue)", function (o) { o.AddRange(X.oids()); }),
    M("void Remove([in] long Index)", function (o) { o.Remove(0); }),
    M("void Clear()", function (o) { o.Clear(); })
], function () { return {}; });

C("CX500DistinguishedName", "IX500DistinguishedName", [
    M("void Encode([in] BSTR strName, [in] X500NameFlags NameFlags)", function (o) { o.Encode("CN=ProbeTest, O=Dev", 0); }),
    M("BSTR get_Name()", function (o) { return o.Name; }),
    M("BSTR get_EncodedName([in] EncodingType Encoding)", function (o) { return "len=" + String(o.EncodedName(1)).length; }),
    M("void Decode([in] BSTR strEncodedName, [in] EncodingType Encoding, [in] X500NameFlags NameFlags)",
      function (o) { o.Decode(o.EncodedName(1), 1, 0); })
]);

C("CX509PrivateKey", "IX509PrivateKey",
    [].concat(
        P("BSTR", "ProviderName", "Microsoft Enhanced RSA and AES Cryptographic Provider"),
        P("X509ProviderType", "ProviderType", 24),
        P("X509KeySpec", "KeySpec", 1),
        P("long", "Length", 2048),
        P("VARIANT_BOOL", "MachineContext", false),
        P("X509PrivateKeyExportFlags", "ExportPolicy", 1),
        P("BSTR", "ContainerName", "X509ComProbeContainer"),
        [
            M("void Create()  // persists a key container", function (o) {
                o.ContainerName = "X509ComProbe" + (new Date()).getTime();
                o.Create();
            }, "unsafe"),
            M("void Delete()  // removes the container created above", function (o) { o.Delete(); }, "unsafe")
        ]
    )
);

C("CX509ExtensionKeyUsage", "IX509ExtensionKeyUsage", extBase([
    M("void InitializeEncode([in] X509KeyUsageFlags UsageFlags)", function (o) { o.InitializeEncode(0xA4); }),
    M("X509KeyUsageFlags get_KeyUsage()", function (o) { return hex(o.KeyUsage); })
]));

C("CX509ExtensionEnhancedKeyUsage", "IX509ExtensionEnhancedKeyUsage", extBase([
    M("void InitializeEncode([in] IObjectIds pValue)", function (o) { o.InitializeEncode(X.oids()); }),
    M("IObjectIds get_EnhancedKeyUsage()", function (o) { return o.EnhancedKeyUsage.Count + " item(s)"; })
]));

C("CX509ExtensionBasicConstraints", "IX509ExtensionBasicConstraints", extBase([
    M("void InitializeEncode([in] VARIANT_BOOL IsCA, [in] long PathLenConstraint)", function (o) { o.InitializeEncode(true, -1); }),
    M("VARIANT_BOOL get_IsCA()", function (o) { return o.IsCA; }),
    M("long get_PathLenConstraint()", function (o) { return o.PathLenConstraint; })
]));

C("CX509ExtensionAlternativeNames", "IX509ExtensionAlternativeNames", extBase([
    M("void InitializeEncode([in] IAlternativeNames pValue)", function (o) { o.InitializeEncode(X.altNames()); }),
    M("IAlternativeNames get_AlternativeNames()", function (o) { return o.AlternativeNames.Count + " item(s)"; })
]));

C("CX509ExtensionSubjectKeyIdentifier", "IX509ExtensionSubjectKeyIdentifier", extBase([
    M("void InitializeEncode([in] EncodingType Encoding, [in] BSTR strKeyIdentifier)",
      function (o) { o.InitializeEncode(4, "0102030405060708090a0b0c0d0e0f1011121314"); }),
    M("BSTR get_SubjectKeyIdentifier([in] EncodingType Encoding)", function (o) { return o.SubjectKeyIdentifier(4); })
]));

C("CX509ExtensionTemplateName", "IX509ExtensionTemplateName", extBase([
    M("void InitializeEncode([in] BSTR strTemplateName)", function (o) { o.InitializeEncode("WebServer"); }),
    M("BSTR get_TemplateName()", function (o) { return o.TemplateName; })
]));

C("CX509Extension", "IX509Extension", [
    M("void Initialize([in] IObjectId pObjectId, [in] EncodingType Encoding, [in] BSTR strEncodedData)",
      function (o) { o.Initialize(X.oid("2.5.29.19"), 1, "MAMBAf8="); }),
    M("IObjectId get_ObjectId()", function (o) { return o.ObjectId.Value; }),
    M("BSTR get_RawData([in] EncodingType Encoding)", function (o) { return "len=" + String(o.RawData(1)).length; }),
    M("VARIANT_BOOL get_Critical()", function (o) { return o.Critical; }),
    M("void put_Critical([in] VARIANT_BOOL)", function (o) { o.Critical = true; return o.Critical; })
]);

C("CX509Extensions", "IX509Extensions", [
    M("void Add([in] IX509Extension pVal)", function (o, st) { st.e = X.ext(); o.Add(st.e); }),
    M("long get_Count()", function (o) { return o.Count; }),
    M("IX509Extension get_ItemByIndex([in] long Index)", function (o) { return o.ItemByIndex(0).ObjectId.Value; }),
    M("long get_IndexByObjectId([in] IObjectId pObjectId)", function (o) { return o.IndexByObjectId(X.oid("2.5.29.19")); }),
    M("void AddRange([in] IX509Extensions pValue)", function (o) {
        var other = mk("CX509Extensions");
        other.Add(X.ext());
        o.AddRange(other);
    }),
    M("void Remove([in] long Index)", function (o) { o.Remove(0); }),
    M("void Clear()", function (o) { o.Clear(); })
]);

C("CAlternativeName", "IAlternativeName", [
    M("void InitializeFromString([in] AlternativeNameType Type, [in] BSTR strValue)", function (o) { o.InitializeFromString(3, "localhost"); }),
    M("AlternativeNameType get_Type()", function (o) { return o.Type; }),
    M("BSTR get_StrValue()", function (o) { return o.StrValue; }),
    M("IObjectId get_ObjectId()  // only meaningful for otherName", function (o) { return o.ObjectId.Value; }),
    M("BSTR get_RawData([in] EncodingType Encoding)", function (o) { return "len=" + String(o.RawData(1)).length; })
]);

C("CAlternativeNames", "IAlternativeNames", [
    M("void Add([in] IAlternativeName pVal)", function (o, st) { st.a = X.altName(); o.Add(st.a); }),
    M("long get_Count()", function (o) { return o.Count; }),
    M("IAlternativeName get_ItemByIndex([in] long Index)", function (o) { return o.ItemByIndex(0).StrValue; }),
    M("long get_IndexByAlternativeName([in] IAlternativeName pVal)", function (o, st) { return o.IndexByAlternativeName(st.a); }),
    M("void Remove([in] long Index)", function (o) { o.Remove(0); }),
    M("void Clear()", function (o) { o.Clear(); })
]);

C("CCspInformations", "ICspInformations", [
    M("void AddAvailableCsps()", function (o) { o.AddAvailableCsps(); }),
    M("long get_Count()", function (o) { return o.Count; }),
    M("ICspInformation get_ItemByIndex([in] long Index)", function (o) { return o.ItemByIndex(0).Name; }),
    M("ICspInformation get_ItemByName([in] BSTR strName)",
      function (o) { return o.ItemByName("Microsoft Enhanced RSA and AES Cryptographic Provider").Name; })
]);

C("CCspInformation", "ICspInformation", [
    M("BSTR get_Name()", function (o, st) { return st.csp.Name; }),
    M("long get_Type()", function (o, st) { return st.csp.Type; }),
    M("VARIANT_BOOL get_IsHardwareDevice()", function (o, st) { return st.csp.IsHardwareDevice; }),
    M("VARIANT_BOOL get_IsRemovable()", function (o, st) { return st.csp.IsRemovable; }),
    M("VARIANT_BOOL get_IsSoftwareDevice()", function (o, st) { return st.csp.IsSoftwareDevice; }),
    M("VARIANT_BOOL get_HasRandomNumberGenerator()", function (o, st) { return st.csp.HasRandomNumberGenerator; })
], function () {
    var list = mk("CCspInformations");
    list.AddAvailableCsps();
    return { csp: list.ItemByIndex(0) };
});

var REQ_COMMON = function (withCertFields) {
    var m = [
        M("void InitializeFromPrivateKey([in] X509CertificateEnrollmentContext Context, [in] IX509PrivateKey pPrivateKey, [in] BSTR strTemplateName)",
          function (o, st) { need(st); o.InitializeFromPrivateKey(1, st.key, ""); }),
        M("void put_Subject([in] IX500DistinguishedName)", function (o, st) { need(st); o.Subject = X.dn(); return "set"; }),
        M("IX500DistinguishedName get_Subject()", function (o, st) { need(st); return o.Subject.Name; })
    ];
    if (withCertFields) {
        m.push(M("void put_Issuer([in] IX500DistinguishedName)", function (o, st) { need(st); o.Issuer = X.dn(); return "set"; }));
        m.push(M("DATE put_NotBefore / put_NotAfter", function (o, st) {
            need(st);
            var a = new Date(); var b = new Date();
            b.setFullYear(b.getFullYear() + 1);
            o.NotBefore = a; o.NotAfter = b;
            return "set";
        }));
        m.push(M("DATE get_NotAfter()", function (o, st) { need(st); return o.NotAfter; }));
    }
    m.push(M("void put_HashAlgorithm([in] IObjectId)", function (o, st) {
        need(st);
        var h = mk("CObjectId");
        h.InitializeFromAlgorithmName(3, 0, 0, "SHA256");
        o.HashAlgorithm = h;
        return "set";
    }));
    m.push(M("IObjectId get_HashAlgorithm()", function (o, st) { need(st); return o.HashAlgorithm.FriendlyName; }));
    m.push(M("IX509Extensions get_X509Extensions()", function (o, st) { need(st); return o.X509Extensions.Count + " ext"; }));
    m.push(M("void Encode()", function (o, st) { need(st); o.Encode(); }));
    m.push(M("BSTR get_RawData([in] EncodingType Encoding)", function (o, st) { need(st); return "len=" + String(o.RawData(1)).length; }));
    m.push(M("void ResetForEncode()", function (o, st) { need(st); o.ResetForEncode(); }));
    return m;
};
var KEY_SETUP = function () { return UNSAFE ? { key: makeTempKey() } : null; };

C("CX509CertificateRequestPkcs10", "IX509CertificateRequestPkcs10", REQ_COMMON(false), KEY_SETUP, dropTempKey);
C("CX509CertificateRequestCertificate", "IX509CertificateRequestCertificate", REQ_COMMON(true), KEY_SETUP, dropTempKey);

C("CX509Enrollment", "IX509Enrollment", [
    M("void Initialize([in] X509CertificateEnrollmentContext Context)", function (o) { o.Initialize(1); }),
    M("void InitializeFromTemplateName([in] Context, [in] BSTR strTemplateName)  // contacts enrollment policy", function () { skip("contacts AD/enrollment policy"); }, "never"),
    M("void InitializeFromRequest([in] IX509CertificateRequest pRequest)", function () { skip("needs a built request, see selfsigned.js"); }, "never"),
    M("BSTR get_CertificateFriendlyName()", function (o) { return o.CertificateFriendlyName; }),
    M("void put_CertificateFriendlyName([in] BSTR)", function (o) { o.CertificateFriendlyName = "Probe"; return "set"; }),
    M("BSTR get_CertificateDescription()", function (o) { return o.CertificateDescription; }),
    M("void put_CertificateDescription([in] BSTR)", function (o) { o.CertificateDescription = "Probe"; return "set"; }),
    M("BSTR CreateRequest([in] EncodingType Encoding)", function () { skip("needs InitializeFromRequest first"); }, "never"),
    M("void Enroll()  // submits to a CA", function () { skip("state changing, never called"); }, "never"),
    M("void InstallResponse([in] InstallResponseRestrictionFlags Restrictions, [in] BSTR strResponse, [in] EncodingType Encoding, [in] BSTR strPassword)  // writes cert store", function () { skip("state changing, never called"); }, "never"),
    M("BSTR CreatePFX([in] BSTR strPassword, [in] PFXExportOptions ExportOptions, [in] EncodingType Encoding)", function () { skip("exports key material, never called"); }, "never"),
    M("void Delete()  // removes the pending request and key", function () { skip("state changing, never called"); }, "never")
]);

// ---------------------------------------------------------------------------
// Step 1: enumerate X509* ProgIDs from HKEY_CLASSES_ROOT
// ---------------------------------------------------------------------------
function enumerateProgIds() {
    var found = [];
    try {
        var reg = GetObject("winmgmts:\\\\.\\root\\default:StdRegProv");
        var inp = reg.Methods_("EnumKey").InParameters.SpawnInstance_();
        inp.hDefKey = 0x80000000;        // HKEY_CLASSES_ROOT
        inp.sSubKeyName = "";
        var res = reg.ExecMethod_("EnumKey", inp);
        if (res.sNames) {
            var names = new VBArray(res.sNames).toArray();
            for (var i = 0; i < names.length; i++) {
                var n = names[i];
                if (/^X509/i.test(n) && !/\.\d+$/.test(n)) { found.push(n); }
            }
        }
    } catch (e) {
        out("(registry enumeration failed: " + e.message + "; falling back to catalog names)");
    }
    return found;
}

function clsidOf(prog) {
    try { return shell.RegRead("HKCR\\" + prog + "\\CLSID\\"); } catch (e) { return "(no CLSID)"; }
}

function canCreate(prog) {
    try { var o = new ActiveXObject(prog); o = null; return true; } catch (e) { return false; }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
function main() {
    out("X509 COM probe   mode=" + MODE + (UNSAFE ? " +unsafe" : "") + "   " + new Date());
    out("");
    out("== Registered X509* ProgIDs (HKCR) ==");

    var registered = enumerateProgIds();
    if (registered.length === 0) {
        for (var c = 0; c < CATALOG.length; c++) { registered.push(CATALOG[c].prog); }
    }
    registered.sort();

    var inCatalog = {};
    for (var k = 0; k < CATALOG.length; k++) { inCatalog[CATALOG[k].prog.toLowerCase()] = CATALOG[k]; }

    var createdOk = 0;
    for (var r = 0; r < registered.length; r++) {
        var p = registered[r];
        var ok = canCreate(p);
        if (ok) { createdOk++; }
        out(pad(p, 54) + pad(ok ? "creatable" : "NOT creatable", 15) +
            (inCatalog[p.toLowerCase()] ? "[catalog]" : "[no catalog entry]"));
    }
    out("");
    out(registered.length + " registered, " + createdOk + " creatable, " + CATALOG.length + " with prototypes.");

    if (MODE === "list") { finish(); return; }

    var total = 0, called = 0, failed = 0, skipped = 0;

    for (var i = 0; i < CATALOG.length; i++) {
        var cls = CATALOG[i];
        out("");
        out("==============================================================================");
        out(cls.prog + "    (" + cls.iface + ")");
        out("==============================================================================");

        var obj = null, st = {}, createErr = "";
        if (MODE === "call") {
            try { obj = new ActiveXObject(cls.prog); }
            catch (e1) { createErr = "cannot create: " + e1.message; }
            if (obj && cls.setup) {
                try { st = cls.setup(); } catch (e2) { st = null; out("  (setup failed: " + e2.message + ")"); }
            }
        }
        if (createErr) { out("  " + createErr); }

        for (var m = 0; m < cls.members.length; m++) {
            var mem = cls.members[m];
            total++;
            var line = "  " + mem.proto;
            if (MODE === "protos") { out(line); continue; }

            var status;
            if (!obj) {
                status = "SKIP  (no instance)"; skipped++;
            } else if (mem.flag === "never") {
                try { mem.fn(obj, st); } catch (e3) { status = "SKIP  " + (e3 && e3.skip ? e3.skip : "not called"); }
                skipped++;
            } else if (mem.flag === "unsafe" && !UNSAFE) {
                status = "SKIP  needs /unsafe"; skipped++;
            } else {
                try {
                    var v = mem.fn(obj, st || {});
                    status = "OK    => " + fmt(v); called++;
                } catch (e4) {
                    if (e4 && e4.skip) { status = "SKIP  " + e4.skip; skipped++; }
                    else {
                        status = "ERR   " + hex(e4.number) + " " + String(e4.message || e4).replace(/[\r\n]+/g, " ");
                        failed++;
                    }
                }
            }
            out(line);
            out("      " + status);
        }

        if (cls.teardown && st) { try { cls.teardown(st); } catch (e5) {} }
    }

    out("");
    if (MODE === "protos") {
        out("Summary: " + total + " prototypes listed.");
    } else {
        out("Summary: " + total + " members, " + called + " called OK, " + failed + " errors, " + skipped + " skipped.");
    }
    finish();
}

function finish() {
    try {
        var f = fso.CreateTextFile(OUTFILE, true, true);
        f.Write(report.join("\r\n"));
        f.Close();
        WScript.Echo("");
        WScript.Echo("Report written to " + fso.GetAbsolutePathName(OUTFILE));
    } catch (e) {
        WScript.Echo("Could not write report: " + e.message);
    }
}

try {
    main();
} catch (e) {
    WScript.Echo("Fatal: " + (e.message || e));
    WScript.Quit(1);
}
