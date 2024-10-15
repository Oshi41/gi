using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Console;
using Vanara.PInvoke;

namespace injector;

internal static class Program
{
    public static void Main(string[] args)
    {
        var logger = LoggerFactory.Create(builder =>
        {
            builder.SetMinimumLevel(Utils.ReadConfig().LogLevel);

            builder.AddSimpleConsole(options =>
            {
                options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss.fff] ";
                options.ColorBehavior = LoggerColorBehavior.Enabled;
                options.SingleLine = true;
                options.UseUtcTimestamp = true;
                options.IncludeScopes = true;
            });
        }).CreateLogger("Injector");
        
        logger.LogInformation("Starting...");

        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
        {
            var adminProc = new Process();

            adminProc.StartInfo.FileName = Process.GetCurrentProcess().MainModule.FileName;
            adminProc.StartInfo.UseShellExecute = true;
            adminProc.StartInfo.Verb = "runas";
            adminProc.Start();
            logger.LogDebug("Restarting as administrator...");
            return;
        }
        logger.LogDebug("Admin role confirmed");

        var cfg = Utils.ReadConfig();
        cfg.ExePath = Path.GetFullPath("TestTarget.exe");
        
        
        if (!AdvApi32.OpenProcessToken(Kernel32.GetCurrentProcess(), AdvApi32.TokenAccess.TOKEN_ALL_ACCESS,
                out var selfToken))
        {
            throw new Exception($"[AdvApi32.OpenProcessToken] Cannot open own proc token: {Kernel32.GetLastError()}");
        }

        logger.LogDebug("Opened self token");

        var currentId = Process.GetCurrentProcess().SessionId;
        // lookup for explorer process
        var exporer = Process.GetProcessesByName("explorer")
            .FirstOrDefault(x => x.SessionId == currentId);
        if (exporer == null)
        {
            throw new Exception("Failed to find explorer.exe");
        }

        logger.LogDebug("Explorer process detected");

        // open explorer process
        var explorerProc = Kernel32.OpenProcess(ACCESS_MASK.GENERIC_ALL, false, (uint)exporer.Id);
        if (explorerProc.IsInvalid)
        {
            throw new Exception("[Kernel32.OpenProcess] Cannot open explorer proc");
        }

        logger.LogDebug("Opened explorer process");

        // getting thread attribute size
        SizeT size = default;
        var startupInfo = Kernel32.STARTUPINFOEX.Default;

        // should return error, lol
        // https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist#remarks
        Kernel32.InitializeProcThreadAttributeList(default, 1, 0, ref size);

        // allocating data and initialize again
        startupInfo.lpAttributeList = Marshal.AllocHGlobal(size);
        if (!Kernel32.InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, ref size))
        {
            throw new Exception(
                $"[Kernel32.InitializeProcThreadAttributeList] Cannot init attributes: {Kernel32.GetLastError()}");
        }

        // copy pointer
        var copy = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(copy, explorerProc.DangerousGetHandle());

        if (!Kernel32.UpdateProcThreadAttribute(startupInfo.lpAttributeList,
                0,
                Kernel32.PROC_THREAD_ATTRIBUTE.PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                copy,
                IntPtr.Size))
        {
            throw new Exception(
                $"[Kernel32.UpdateProcThreadAttribute] Cannot update parent proc: {Kernel32.GetLastError()}");
        }

        logger.LogDebug("Thread attributes prepared");

        if (!AdvApi32.CreateProcessAsUser(selfToken,
                cfg.ExePath,
                null,
                null,
                null,
                false,
                Kernel32.CREATE_PROCESS.EXTENDED_STARTUPINFO_PRESENT | Kernel32.CREATE_PROCESS.CREATE_SUSPENDED,
                null,
                Path.GetDirectoryName(cfg.ExePath),
                startupInfo,
                out var gameProc))
        {
            throw new Exception(
                $"[AdvApi32.CreateProcessAsUser] Cannot create suspended Anime Process: {Kernel32.GetLastError()}");
        }

        logger.LogInformation("Anime game process started");

        // clear memory
        Kernel32.DeleteProcThreadAttributeList(startupInfo.lpAttributeList);
        Marshal.FreeHGlobal(startupInfo.lpAttributeList);
        Marshal.FreeHGlobal(copy);

        // get loaded kernel module
        var kernelHandle = Kernel32.GetModuleHandle(Lib.Kernel32);
        if (kernelHandle.IsInvalid)
        {
            throw new Exception(
                $"[Kernel32.GetModuleHandle] Cannot find loaded {Lib.Kernel32} module: {Kernel32.GetLastError()}");
        }

        logger.LogDebug("Loaded Kernel module founded");

        // get loaded kernel module function
        var loadLibraryFn = Kernel32.GetProcAddress(kernelHandle, "LoadLibraryA");
        if (loadLibraryFn == IntPtr.Zero)
        {
            throw new Exception(
                $"[Kernel32.GetProcAddress] Cannot load {Lib.Kernel32}.LoadLibraryA() function pointer: {Kernel32.GetLastError()}");
        }

        logger.LogDebug("Loaded Kernel LoadLibraryA function founded");

        var dllPathStr = Path.GetFullPath(cfg.LibName);

        // trying to allocate memory in game process
        var dllPath = Kernel32.VirtualAllocEx(gameProc.hProcess, IntPtr.Zero, dllPathStr.Length + 1,
            Kernel32.MEM_ALLOCATION_TYPE.MEM_RESERVE | Kernel32.MEM_ALLOCATION_TYPE.MEM_COMMIT,
            Kernel32.MEM_PROTECTION.PAGE_READWRITE);
        if (dllPath == IntPtr.Zero)
        {
            throw new Exception($"[Kernel32.VirtualAllocEx] Cannot allocate memory: {Kernel32.GetLastError()}");
        }

        logger.LogDebug("Memory allocated, ready to load library");

        // Write the string name of our DLL in the memory allocated
        if (!Kernel32.WriteProcessMemory(gameProc.hProcess,
                dllPath,
                Encoding.UTF8.GetBytes(dllPathStr),
                Encoding.UTF8.GetBytes(dllPathStr).Length,
                out _))
        {
            throw new Exception($"[Kernel32.WriteProcessMemory] Cannot write memory: {Kernel32.GetLastError()}");
        }

        logger.LogDebug("Library path written");

        // calling load library
        var thread = Kernel32.CreateRemoteThread(gameProc.hProcess, null, default, loadLibraryFn, dllPath,
            Kernel32.CREATE_THREAD_FLAGS.RUN_IMMEDIATELY, out _);
        if (thread.IsInvalid)
        {
            throw new Exception(
                $"[Kernel32.CreateRemoteThread] Cannot inject dll: {dllPathStr}: {Kernel32.GetLastError()}");
        }
        
        logger.LogDebug("Kernel34.LoadLibraryA() called");

        // Waiting for thread end and release unnecessary data
        if (Kernel32.WaitForSingleObject(thread, 2000) == Kernel32.WAIT_STATUS.WAIT_OBJECT_0)
        {
            if (!Kernel32.VirtualFreeEx(gameProc.hProcess, dllPath, 0, Kernel32.MEM_ALLOCATION_TYPE.MEM_RELEASE))
            {
                throw new Exception($"[Kernel32.VirtualFreeEx] Cannot free memory: {Kernel32.GetLastError()}");
            }

            logger.LogDebug("Clean loaded DLL fullpath");
        }

        if (!Kernel32.CloseHandle(thread.DangerousGetHandle()))
        {
            throw new Exception($"[Kernel32.CloseHandle] Cannot close handle: {Kernel32.GetLastError()}");
        }

        logger.LogDebug("Closing injection thread");

        // continue thread
        Kernel32.ResumeThread(gameProc.hThread);

        logger.LogInformation("DLL was injected, starting game...");

        // wait a sec for thread to run
        Task.Delay(1000).Wait();
        
        var game = Process.GetProcessById((int)gameProc.dwProcessId);
        
        AppDomain.CurrentDomain.ProcessExit += (sender, args) =>
        {
            game.Kill();
        };

        logger.LogInformation("Game started");
        game.WaitForExit();
    }
}