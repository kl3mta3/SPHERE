using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SPHERE.Configure.Logging
{
    internal class SystemLogger
    {
        private static readonly string logFilePath = "logs/SPHERE.log";

        public static void Log(string message)
        {
            bool isTesting = Environment.GetEnvironmentVariable("SPHERE_TEST_MODE") == "true";

            if (!isTesting)
            {
                try
                {

                    string directoryPath = Path.GetDirectoryName(logFilePath);

                    if (!Directory.Exists(directoryPath))
                    {
                        Directory.CreateDirectory(directoryPath);
                    }


                    string logEntry = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}";


                    Console.WriteLine(logEntry);
                    File.AppendAllText(logFilePath, logEntry + Environment.NewLine);
                }
                catch (Exception ex)
                {

                    Console.WriteLine($"Logging failed: {ex.Message}");
                }
            }
        }

    }
}
