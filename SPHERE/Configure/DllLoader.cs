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
        public static void LoadAllEmbeddedDlls()
        {
            var assembly = Assembly.GetExecutingAssembly();
            var resourceNames = assembly.GetManifestResourceNames();

            foreach (var resourceName in resourceNames)
            {
                if (resourceName.StartsWith("SPHERE.Libs.") && resourceName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                {
                    using (var stream = assembly.GetManifestResourceStream(resourceName))
                    {
                        if (stream == null)
                        {
                            throw new InvalidOperationException($"Resource {resourceName} not found.");
                        }

                        var buffer = new byte[stream.Length];
                        stream.Read(buffer, 0, buffer.Length);
                        Assembly.Load(buffer);
                    }
                }
            }

            Console.WriteLine("All DLLs in SPHERE/Libs loaded successfully.");
        }
    }
}
