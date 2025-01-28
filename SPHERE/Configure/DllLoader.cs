using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Configure
{
    public static class DllLoader
    {
        // Static constructor to handle DLL loading on first use of the library
        static DllLoader()
        {
            AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
            {
                try
                {
                    string resourceName = args.Name.Split(',')[0] + ".dll";
                    var assembly = Assembly.GetExecutingAssembly();
                    using (var stream = assembly.GetManifestResourceStream($"SPHERE.Libs.{resourceName}"))
                    {
                        if (stream == null) return null;
                        var buffer = new byte[stream.Length];
                        stream.Read(buffer, 0, buffer.Length);
                        return Assembly.Load(buffer);
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to resolve assembly: {args.Name}. Error: {ex.Message}");
                    return null;
                }
            };
        }

        // Optional method to allow manual initialization, if necessary
        public static void Initialize()
        {
            // This method can be empty; calling it ensures the static constructor runs
        }
    }
}

