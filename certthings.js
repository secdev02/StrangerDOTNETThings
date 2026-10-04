// selfsigned.js
// Creates a self-signed X.509 certificate and trusts it for the CURRENT USER only.
// No admin rights needed. Run with:  cscript //nologo selfsigned.js
//
// Result:
//   - Cert + private key in   CurrentUser\My   (Personal)
//   - Cert (public part) in   CurrentUser\Root (Trusted Root Certification Authorities)
//
// Windows will show a one-time security prompt when adding to the Root store.
// Click "Yes" to accept it.

// ---------------- Settings ----------------
var COMMON_NAME  = "localhost";
var DNS_NAMES    = ["localhost", "mydev.local"];  // Subject Alternative Names
var FRIENDLY     = "Dev Self-Signed (" + COMMON_NAME + ")";
var VALID_YEARS  = 2;
var KEY_BITS     = 2048;
// ------------------------------------------

var XCN_AT_KEYEXCHANGE            = 1;
var ContextUser                   = 1;
var XCN_CRYPT_STRING_BASE64HEADER = 0;
var XCN_CRYPT_HASH_ALG_OID_GROUP_ID = 3;
var XCN_CERT_ALT_NAME_DNS_NAME    = 3;
var AllowUntrustedCertificate     = 2;
var XCN_NCRYPT_ALLOW_EXPORT_FLAG  = 1;
var XCN_NCRYPT_ALLOW_ALL_USAGES   = 0xffffff;

// Key usage bits: digitalSignature | keyEncipherment | keyCertSign
var KEY_USAGE = 0x80 | 0x20 | 0x04;

var shell = new ActiveXObject("WScript.Shell");
var fso   = new ActiveXObject("Scripting.FileSystemObject");

function main() {
    // 1. Private key
    var key = new ActiveXObject("X509Enrollment.CX509PrivateKey");
    key.ProviderName   = "Microsoft Enhanced RSA and AES Cryptographic Provider";
    key.ProviderType   = 24;
    key.KeySpec        = XCN_AT_KEYEXCHANGE;
    key.Length         = KEY_BITS;
    key.MachineContext = false;
    key.ExportPolicy   = XCN_NCRYPT_ALLOW_EXPORT_FLAG;
    key.KeyUsage       = XCN_NCRYPT_ALLOW_ALL_USAGES;
    key.Create();

    // 2. Self-signed certificate object
    var cert = new ActiveXObject("X509Enrollment.CX509CertificateRequestCertificate");
    cert.InitializeFromPrivateKey(ContextUser, key, "");

    var dn = new ActiveXObject("X509Enrollment.CX500DistinguishedName");
    dn.Encode("CN=" + COMMON_NAME, 0);
    cert.Subject = dn;
    cert.Issuer  = dn;   // same as subject => self-signed

    var now = new Date();
    var start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    var end = new Date(now.getTime());
    end.setFullYear(end.getFullYear() + VALID_YEARS);
    cert.NotBefore = start;
    cert.NotAfter  = end;

    // Hash algorithm: SHA256
    var hashOid = new ActiveXObject("X509Enrollment.CObjectId");
    hashOid.InitializeFromAlgorithmName(XCN_CRYPT_HASH_ALG_OID_GROUP_ID, 0, 0, "SHA256");
    cert.HashAlgorithm = hashOid;

    // 3. Extensions
    var ku = new ActiveXObject("X509Enrollment.CX509ExtensionKeyUsage");
    ku.InitializeEncode(KEY_USAGE);
    cert.X509Extensions.Add(ku);

    var ekuOids = new ActiveXObject("X509Enrollment.CObjectIds");
    var serverAuth = new ActiveXObject("X509Enrollment.CObjectId");
    serverAuth.InitializeFromValue("1.3.6.1.5.5.7.3.1");
    ekuOids.Add(serverAuth);
    var clientAuth = new ActiveXObject("X509Enrollment.CObjectId");
    clientAuth.InitializeFromValue("1.3.6.1.5.5.7.3.2");
    ekuOids.Add(clientAuth);
    var eku = new ActiveXObject("X509Enrollment.CX509ExtensionEnhancedKeyUsage");
    eku.InitializeEncode(ekuOids);
    cert.X509Extensions.Add(eku);

    var bc = new ActiveXObject("X509Enrollment.CX509ExtensionBasicConstraints");
    bc.InitializeEncode(true, -1);
    cert.X509Extensions.Add(bc);

    var names = new ActiveXObject("X509Enrollment.CAlternativeNames");
    for (var i = 0; i < DNS_NAMES.length; i++) {
        var an = new ActiveXObject("X509Enrollment.CAlternativeName");
        an.InitializeFromString(XCN_CERT_ALT_NAME_DNS_NAME, DNS_NAMES[i]);
        names.Add(an);
    }
    var san = new ActiveXObject("X509Enrollment.CX509ExtensionAlternativeNames");
    san.InitializeEncode(names);
    cert.X509Extensions.Add(san);

    cert.Encode();

    // 4. Install into CurrentUser\My (Personal) with its private key
    var enroll = new ActiveXObject("X509Enrollment.CX509Enrollment");
    enroll.InitializeFromRequest(cert);
    enroll.CertificateFriendlyName = FRIENDLY;
    var response = enroll.CreateRequest(XCN_CRYPT_STRING_BASE64HEADER);
    enroll.InstallResponse(AllowUntrustedCertificate, response, XCN_CRYPT_STRING_BASE64HEADER, "");

    // 5. Export the public cert to a temp file and add it to CurrentUser\Root
    var tmpPath = fso.BuildPath(fso.GetSpecialFolder(2), fso.GetTempName() + ".cer");
    var f = fso.CreateTextFile(tmpPath, true, false);   // ASCII
    f.Write(cert.RawData(XCN_CRYPT_STRING_BASE64HEADER));
    f.Close();

    var cmd = 'certutil.exe -user -addstore -f Root "' + tmpPath + '"';
    var rc = shell.Run(cmd, 0, true);

    try { fso.DeleteFile(tmpPath); } catch (e) {}

    if (rc !== 0) {
        throw new Error("certutil returned exit code " + rc +
            ". The Root store prompt may have been declined.");
    }

    WScript.Echo("Done. Certificate for CN=" + COMMON_NAME + " created and trusted for the current user.");
    WScript.Echo("Valid until: " + end.toDateString());
    WScript.Echo("To remove it later, open certmgr.msc and delete it from Personal and Trusted Root.");
}

try {
    main();
} catch (e) {
    WScript.Echo("Failed: " + (e.message || e));
    WScript.Quit(1);
}

