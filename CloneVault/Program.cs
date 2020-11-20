using Microsoft.Win32.SafeHandles;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

// This code built on top of the code in this project:
// https://gist.github.com/meziantou/10311113
// with a few other ideas from:
// https://github.com/AdysTech/CredentialManager

namespace CloneVault
{
    public static class CredentialManager
    {
        private struct ExportCred
        {
            public uint Flags;
            public CredentialType Type;
            public string TargetName;
            public string Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public byte[] CredentialBlob;
            public uint Persist;
            public int AttributeCount;
            public ExportAttrib[] Attributes;
            public int AttributesLength;
            public string TargetAlias;
            public string UserName;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct NativeCredentialAttribute
        {
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Keyword;
            public UInt32 Flags;
            public UInt32 ValueSize;
            public IntPtr Value;
        }

        private struct ExportAttrib
        {
            public string Keyword;
            public UInt32 Flags;
            public UInt32 ValueSize;
            public Byte[] Value;
        }

        public static void ExportCredentialPtr(IntPtr nCredPtr)
        {
            using (CriticalCredentialHandle critCred = new CriticalCredentialHandle(nCredPtr))
            {
                CREDENTIAL cred = critCred.GetCredential();
                uint Flags = cred.Flags;
                CredentialType Type = cred.Type;
                string TargetName = Marshal.PtrToStringUni(cred.TargetName);
                string Comment = Marshal.PtrToStringUni(cred.Comment);
                System.Runtime.InteropServices.ComTypes.FILETIME LastWritten = cred.LastWritten;
                uint CredentialBlobSize = cred.CredentialBlobSize;
                var data = new byte[CredentialBlobSize];

                if (CredentialBlobSize > 0)
                {
                    Marshal.Copy(cred.CredentialBlob, data, 0, data.Length);
                }
                uint Persist = cred.Persist;
                int AttributeCount = cred.AttributeCount;


                var attribSize = Marshal.SizeOf(typeof(NativeCredentialAttribute));

                
                ExportAttrib[] attribs = new ExportAttrib[AttributeCount];
                if (AttributeCount > 0)
                {
                    byte[] rawData = new byte[AttributeCount * attribSize];
                    var buffer = Marshal.AllocHGlobal(attribSize);
                    Marshal.Copy(cred.Attributes, rawData, (int)0, (int)AttributeCount * attribSize);



                    for (int i = 0; i < AttributeCount; i++)
                    {
                        Marshal.Copy(rawData, i * attribSize, buffer, attribSize);
                        var attr = (NativeCredentialAttribute)Marshal.PtrToStructure(buffer,
                         typeof(NativeCredentialAttribute));
                        var key = attr.Keyword;
                        var val = new byte[attr.ValueSize];
                        Marshal.Copy(attr.Value, val, (int)0, (int)attr.ValueSize);
                        Console.WriteLine("[-] Attribute {0}", key);

                        ExportAttrib attrib = new ExportAttrib();
                        attrib.Keyword = attr.Keyword;
                        attrib.Flags = attr.Flags;
                        attrib.ValueSize = attr.ValueSize;
                        attrib.Value = val;

                        attribs[i] = attrib;
                    }
                }

                string TargetAlias = Marshal.PtrToStringUni(cred.TargetAlias);
                string UserName = Marshal.PtrToStringUni(cred.UserName);

                ExportCred export = new ExportCred();
                export.Flags = Flags;
                export.Type = Type;
                export.TargetName = TargetName;
                export.Comment = Comment;
                export.LastWritten = LastWritten;
                export.CredentialBlobSize = CredentialBlobSize;
                export.CredentialBlob = data;
                export.Persist = Persist;
                export.AttributeCount = AttributeCount;
                export.AttributesLength = AttributeCount * attribSize;
                export.Attributes = attribs;
                export.TargetAlias = TargetAlias;
                export.UserName = UserName;

                Console.WriteLine(JsonConvert.SerializeObject(export).Replace("\"", "'"));
            }
        }

        public static void ExportCredential(string applicationName)
        {
            Console.WriteLine("[*] Attempting to export {0}", applicationName);

            IntPtr nCredPtr;
            bool read = CredRead(applicationName, CredentialType.Generic, 0, out nCredPtr);

            if (!read)
            {
                Console.WriteLine("Failed to read {0}", applicationName);
            }

            if (read)
            {
                ExportCredentialPtr(nCredPtr);
            }
        }

        public static void RestoreCredential(string jsonString, bool fromFile = false)
        {
            Console.WriteLine("[*] Importing credential");

            if (fromFile)
            {
                jsonString = System.IO.File.ReadAllText(jsonString);
            }

            ExportCred export = JsonConvert.DeserializeObject<ExportCred>(jsonString);

            CREDENTIAL new_cred = new CREDENTIAL();
            new_cred.Flags = export.Flags;
            new_cred.Type = export.Type;
            new_cred.TargetName = Marshal.StringToCoTaskMemUni(export.TargetName);
            new_cred.Comment = Marshal.StringToCoTaskMemUni(export.Comment);
            new_cred.LastWritten = export.LastWritten;
            new_cred.CredentialBlobSize = export.CredentialBlobSize;
            int size = export.CredentialBlob.Length;
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(size);
            Marshal.Copy(export.CredentialBlob, 0, unmanagedPointer, export.CredentialBlob.Length);
            new_cred.CredentialBlob = unmanagedPointer;
            new_cred.Persist = export.Persist;
            new_cred.AttributeCount = export.AttributeCount;

            var asize = Marshal.SizeOf(typeof(NativeCredentialAttribute));

            byte[] oadata = new byte[export.AttributesLength];
            List<IntPtr> attributesToFree = new List<IntPtr>();

            for (int n = 0; n < export.AttributeCount; n++)
            {
                ExportAttrib attrib = export.Attributes[n];

                Console.WriteLine("[-] Attribute {0}", attrib.Keyword);

                NativeCredentialAttribute nativeAttrib = new NativeCredentialAttribute();
                nativeAttrib.Keyword = attrib.Keyword;
                nativeAttrib.Flags = attrib.Flags;
                nativeAttrib.ValueSize = attrib.ValueSize;

                IntPtr ptrattribvalue = Marshal.AllocHGlobal((int)attrib.ValueSize);
                attributesToFree.Add(ptrattribvalue);
                Marshal.Copy(attrib.Value, 0, ptrattribvalue, (int)attrib.ValueSize);

                nativeAttrib.Value = ptrattribvalue;

                var attrbuff = Marshal.AllocHGlobal(asize);
                attributesToFree.Add(attrbuff);
                Marshal.StructureToPtr(nativeAttrib, attrbuff, false);
                Marshal.Copy(attrbuff, oadata, n * asize, asize);
            }

            GCHandle pinnedAttributes = default(GCHandle);
            pinnedAttributes = GCHandle.Alloc(oadata, GCHandleType.Pinned);

            new_cred.Attributes = pinnedAttributes.AddrOfPinnedObject();
            new_cred.TargetAlias = Marshal.StringToCoTaskMemUni(export.TargetAlias);
            new_cred.UserName = Marshal.StringToCoTaskMemUni(export.UserName);

            bool written = CredWrite(ref new_cred, 0);

            Marshal.FreeCoTaskMem(new_cred.TargetAlias);
            Marshal.FreeCoTaskMem(new_cred.TargetName);
            Marshal.FreeCoTaskMem(new_cred.UserName);
            Marshal.FreeCoTaskMem(new_cred.Comment);
            Marshal.FreeHGlobal(unmanagedPointer);
            pinnedAttributes.Free();
            foreach(IntPtr attributeToFree in attributesToFree)
            {
                Marshal.FreeHGlobal(attributeToFree);
            }

            if (!written)
            {
                int lastError = Marshal.GetLastWin32Error();
                throw new Exception(string.Format("CredWrite failed with the error code {0}.", lastError));
            }

            Console.WriteLine("[*] Finished importing credential");
        }

        private static Credential ReadCredential(CREDENTIAL credential)
        {
            string applicationName = Marshal.PtrToStringUni(credential.TargetName);
            string userName = Marshal.PtrToStringUni(credential.UserName);
            string secret = null;
            if (credential.CredentialBlob != IntPtr.Zero)
            {
                secret = Marshal.PtrToStringUni(credential.CredentialBlob, (int)credential.CredentialBlobSize / 2);
            }

            return new Credential(credential.Type, applicationName, userName, secret);
        }

        public static void EnumerateCrendentials()
        {
            Console.WriteLine("[*] Enumerating generic credentials");
            List<Credential> result = new List<Credential>();
            int count;
            IntPtr pCredentials;
            bool ret = CredEnumerate(null, 1, out count, out pCredentials);
            if (ret)
            {
                for (int n = 0; n < count; n++)
                {
                    IntPtr credential = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)));
                    Credential cred = ReadCredential((CREDENTIAL)Marshal.PtrToStructure(credential, typeof(CREDENTIAL))); 
                    if (cred.CredentialType == CredentialType.Generic)
                    {
                        Console.WriteLine("[-] {0}", cred.ApplicationName);
                    }
                }
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                Console.WriteLine(lastError);
                throw new Win32Exception(lastError);
            }
        }

        public static void ExportAllCredentials()
        {
            Console.WriteLine("[*] Exporting all credentials");
            List<Credential> result = new List<Credential>();
            int count;
            IntPtr pCredentials;
            bool ret = CredEnumerate(null, 1, out count, out pCredentials);
            if (ret)
            {
                for (int n = 0; n < count; n++)
                {
                    IntPtr credential = Marshal.ReadIntPtr(pCredentials, n * Marshal.SizeOf(typeof(IntPtr)));
                    Credential cred = ReadCredential((CREDENTIAL)Marshal.PtrToStructure(credential, typeof(CREDENTIAL)));
                    if (cred.CredentialType == CredentialType.Generic)
                    {
                        try
                        {
                            ExportCredential(cred.ApplicationName);
                        }
                        catch
                        {
                            Console.WriteLine("[!] Failed to export {0}", cred.ApplicationName);
                        }
                        Console.WriteLine("");
                    }
                }
            }
            else
            {
                int lastError = Marshal.GetLastWin32Error();
                Console.WriteLine(lastError);
                throw new Win32Exception(lastError);
            }
        }

        [DllImport("Advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredRead(string target, CredentialType type, int reservedFlag, out IntPtr credentialPtr);

        [DllImport("Advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CredWrite([In] ref CREDENTIAL userCredential, [In] UInt32 flags);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool CredEnumerate(string filter, int flag, out int count, out IntPtr pCredentials);

        [DllImport("Advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
        static extern bool CredFree([In] IntPtr cred);

        private enum CredentialPersistence : uint
        {
            Session = 1,
            LocalMachine,
            Enterprise
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct CREDENTIAL
        {
            public uint Flags;
            public CredentialType Type;
            public IntPtr TargetName;
            public IntPtr Comment;
            public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
            public uint CredentialBlobSize;
            public IntPtr CredentialBlob;
            public uint Persist;
            public int AttributeCount;
            public IntPtr Attributes;
            public IntPtr TargetAlias;
            public IntPtr UserName;
        }

        sealed class CriticalCredentialHandle : CriticalHandleZeroOrMinusOneIsInvalid
        {
            public CriticalCredentialHandle(IntPtr preexistingHandle)
            {
                SetHandle(preexistingHandle);
            }

            public CREDENTIAL GetCredential()
            {
                if (!IsInvalid)
                {
                    CREDENTIAL credential = (CREDENTIAL)Marshal.PtrToStructure(handle, typeof(CREDENTIAL));
                    return credential;
                }

                throw new InvalidOperationException("Invalid CriticalHandle!");
            }

            protected override bool ReleaseHandle()
            {
                if (!IsInvalid)
                {
                    CredFree(handle);
                    SetHandleAsInvalid();
                    return true;
                }

                return false;
            }
        }
    }

    public enum CredentialType
    {
        Generic = 1,
        DomainPassword,
        DomainCertificate,
        DomainVisiblePassword,
        GenericCertificate,
        DomainExtended,
        Maximum,
        MaximumEx = Maximum + 1000,
    }

    public class Credential
    {
        private readonly string _applicationName;
        private readonly string _userName;
        private readonly string _password;
        private readonly CredentialType _credentialType;

        public CredentialType CredentialType
        {
            get { return _credentialType; }
        }

        public string ApplicationName
        {
            get { return _applicationName; }
        }

        public string UserName
        {
            get { return _userName; }
        }

        public string Password
        {
            get { return _password; }
        }

        public Credential(CredentialType credentialType, string applicationName, string userName, string password)
        {
            _applicationName = applicationName;
            _userName = userName;
            _password = password;
            _credentialType = credentialType;
        }

        public override string ToString()
        {
            return string.Format("CredentialType: {0}, ApplicationName: {1}, UserName: {2}, Password: {3}", CredentialType, ApplicationName, UserName, Password);
        }
    }

    class Program
    {
        static void Main(string[] args)
        {

            if(args.Length == 2 || args.Length == 1)
            {
                if(args[0] == "export")
                {
                    CredentialManager.ExportCredential(args[1]);
                }

                if (args[0] == "exportAll")
                {
                    CredentialManager.ExportAllCredentials();
                }

                if (args[0] == "import")
                {
                    CredentialManager.RestoreCredential(args[1]);
                }

                if (args[0] == "importFile")
                {
                    CredentialManager.RestoreCredential(args[1], true);
                }

                if (args[0] == "list")
                {
                    CredentialManager.EnumerateCrendentials();
                }
            }
            else
            {
                Console.WriteLine("CloneVault.exe list");
                Console.WriteLine("CloneVault.exe export <application name>");
                Console.WriteLine("CloneVault.exe exportAll");
                Console.WriteLine("CloneVault.exe import <JSON string>");
                Console.WriteLine("CloneVault.exe importFile <JSON file>");
            }

            
        }
    }
}
