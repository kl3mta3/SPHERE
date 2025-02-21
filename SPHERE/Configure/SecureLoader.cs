using System;
using System.IO;
using System.Reflection;

namespace SPHERE.Configure
{



    public static class SecureLoader
    {
    //    private static bool _isLoaded = false;

    //    public static void EnsureLoaded()
    //    {
    //        if (_isLoaded) return; // Prevent redundant loading
    //        _isLoaded = true;

    //        string basePath = AppDomain.CurrentDomain.BaseDirectory;
    //        string[] possiblePaths =
    //        {
    //    Path.Combine(basePath, "Packet.dll"), // Standard location
    //    Path.Combine(basePath, "libs", "Packet.dll"), // Alternative "libs" directory
    //    Path.Combine(basePath, "bin", "Packet.dll"), // If it's inside a bin folder
    //    Path.Combine(basePath, "lib", "net8.0", "Packet.dll") // NuGet installation path
    //};

    //        string packetDllPath = possiblePaths.FirstOrDefault(File.Exists)
    //            ?? throw new FileNotFoundException("Packet.dll not found in expected locations.");

    //        SystemLogger.Log($"[INFO] Dynamically loading Packet.dll from: {packetDllPath}");

    //        // 🔥 Load with LoadFrom() to properly register the assembly
    //        Assembly packetAssembly = Assembly.LoadFrom(packetDllPath);

    //        // 🔄 Validate successful loading
    //        if (packetAssembly == null)
    //            throw new InvalidOperationException("Failed to load Packet.dll into AppDomain.");

    //        SystemLogger.Log("[INFO] Packet.dll loaded successfully.");
    //    }

    }
}
