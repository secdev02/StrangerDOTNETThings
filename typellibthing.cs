using System;
using System.IO;
using System.Reflection;
using System.Reflection.Emit;
using System.Runtime.InteropServices;
using System.Runtime.InteropServices.ComTypes;

class Program
{
    [DllImport("oleaut32.dll", CharSet = CharSet.Unicode, PreserveSig = false)]
    static extern ITypeLib LoadTypeLibEx(string file, int regKind);

    // Needed so the converter can resolve dependent type libs (e.g. stdole)
    class Sink : ITypeLibImporterNotifySink
    {
        int _n;
        public void ReportEvent(ImporterEventKind kind, int code, string msg) { }

        public Assembly ResolveRef(object typeLib)
        {
            var conv = new TypeLibConverter();
            _n++;
            return conv.ConvertTypeLibToAssembly(
                typeLib, "RefLib" + _n + ".dll", 0, this, null, null, null, null);
        }
    }

    static void Main()
    {
        string tlb = Path.Combine(Environment.SystemDirectory, "wshom.ocx");
        ITypeLib lib = LoadTypeLibEx(tlb, 2); // 2 = REGKIND_NONE

        var conv = new TypeLibConverter();
        AssemblyBuilder ab = conv.ConvertTypeLibToAssembly(
            lib, "Interop.WshLib.dll", 0, new Sink(),
            null, null, "IWshRuntimeLibrary", null);

        // Optional: persist the generated assembly to disk
        ab.Save("Interop.WshLib.dll");

        Type cls = ab.GetType("IWshRuntimeLibrary.WshShellClass");
        object shell = Activator.CreateInstance(cls);

        // Popup(Text, SecondsToWait, Title, Type) ; 64 = information icon
        cls.InvokeMember("Popup", BindingFlags.InvokeMethod, null, shell,
            new object[] { "Hello from a converted type library", 0, "TLB Demo", 64 });
    }
}