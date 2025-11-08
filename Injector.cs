// code from https://www.youtube.com/watch?v=gtlPnxe7abw

#!/usr/bin/env dotnet

#:property InvariantGlobalization=true
#:property TargetFramework=net10.0-windows
#:property RuntimeIdentifier=win-x64
#:property PublishAot=false
#:property IsAotCompatible=false

#:package Iced@1.21.0
#:package Spectre.Console@0.51.1
#:package Spectre.Console.Cli@0.51.1
#:package Microsoft.Windows.CsWin32@0.3.205

#pragma warning disable

using Iced.Intel;
using Spectre.Console;
using Spectre.Console.Cli;
using Spectre.Console.Extensions;
using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.System.Memory;
using Windows.Win32.System.Threading;

using static Iced.Intel.AssemblerRegisters;

CommandApp<InjectCommand> app = new();
app.WithDescription("Injecting dotnet runtime into a process");
return await app.RunAsync(args);

file sealed class InjectSettings : CommandSettings
{
  [CommandArgument(0, "<assembly>")]
  [Description("Managed library to inject")]
  public required string AssemblyPath { get; init; }

  [CommandArgument(0, "<process>")]
  [Description("Process name to inject")]
  public required string ProcessName { get; init; }

  [CommandOption("-e|--entry")]
  [DefaultValue("Main")]
  [Description("Entry method to call, method must be in --type and have signature `static int(IntPtr, int)`")]
  public required string EntryMethod { get; init; }

  [CommandOption("-t|--type")]
  [DefaultValue("App.EntryPoint")]
  [Description("Type in <assembly> which contains --entry, must be `static`.")]
  public string? Type { get; init; }

  public override ValidationResult Validate()
  {
    if (!File.Exists(AssemblyPath)) {
      return ValidationResult.Error("Assembly must exist");
    }
    return ValidationResult.Success();
  }
}

file sealed class InjectCommand : AsyncCommand<InjectSettings>
{
  public override async Task<int> ExecuteAsync(CommandContext context, InjectSettings settings)
  {
    AnsiConsole.MarkupLine(
    """
      Welcome to [purple bold]dotnet injector[/].
      Press Ctrl+C to shutdown.

    """);
    return await AnsiConsole
      .Status()
      .AutoRefresh(true)
      .SpinnerStyle(Style.Parse("green"))
      .Spinner(Spinner.Known.Dots)
      .StartAsync("Initializing...", async ctx => {
        using CancellationTokenSource cts = new();
        CancellationToken cancellationToken = cts.Token;

        try {
          if (Environment.UserInteractive) {
            Console.CancelKeyPress += (s, e) => {
              e.Cancel = true;
              ctx.Status("[bold yellow]Ctrl+C sended.[/] Shutdown...").SpinnerStyle(Style.Parse("red")).Spinner(Spinner.Known.Dots);
              cts.Cancel();
            };
          }

          string assemblyName = Path.GetFileNameWithoutExtension(settings.AssemblyPath);

          ctx.Status($"Searching dotnet version from runtime config of assembly [yellow]\"{assemblyName}\"[/]");

          string dllPath = Path.GetFullPath(settings.AssemblyPath);
          string runtimeConfigPath = Path.GetFullPath(Path.Combine(
            Path.GetDirectoryName(settings.AssemblyPath)!,
            $"{assemblyName}.runtimeconfig.json"
          ));

          if (!File.Exists(dllPath)) {
            throw new FileNotFoundException("Can't find assembly", dllPath);
          }

          if (!File.Exists(runtimeConfigPath)) {
            throw new FileNotFoundException("Can't find runtimeconfig.json", runtimeConfigPath);
          }

          string fxVersion = await GetFrameworkVersionAsync(runtimeConfigPath, cancellationToken);
          AnsiConsole.MarkupLineInterpolated($"Assembly framework version is [blue]\"{fxVersion}\"[/]");
          ctx.Status($"Searching for hostfxr [blue]{fxVersion}[/]..");

          string dotnet = FindDotnetHostPath()
            ?? throw new FileNotFoundException("Can't find dotnet executable");
          string dotnetRoot = Path.GetDirectoryName(dotnet)!;
          string hostfxrPath = Path.Combine(dotnetRoot, "host", "fxr", fxVersion, "hostfxr.dll");

          if (!File.Exists(hostfxrPath)) {
            throw new FileNotFoundException("Can't find the hostfxr", hostfxrPath);
          }
          AnsiConsole.MarkupLineInterpolated($"hostfxr.dll is located [yellow bold]\"{hostfxrPath}\"[/]");

          ctx.Status($"Search process with name [yellow]\"{settings.ProcessName}\"[/]");

          Process process = await FindProcessByNameAsync(settings.ProcessName, cancellationToken);
          AnsiConsole.MarkupLineInterpolated($"Found the process with PID [red]\"{process.Id}\"[/]");
          ctx.Status($"Injecting to process with PID [red]\"{process.Id}\"[/]...");

          // processAccessRights = 0x43a
          const PROCESS_ACCESS_RIGHTS processAccessRights = PROCESS_ACCESS_RIGHTS.PROCESS_VM_READ
              | PROCESS_ACCESS_RIGHTS.PROCESS_VM_WRITE
              | PROCESS_ACCESS_RIGHTS.PROCESS_VM_OPERATION
              | PROCESS_ACCESS_RIGHTS.PROCESS_CREATE_THREAD
              | PROCESS_ACCESS_RIGHTS.PROCESS_QUERY_INFORMATION;

          HANDLE processHandle = default;

          try {
            processHandle = PInvoke.OpenProcess(
              processAccessRights,
              bInheritHandle: false,
              (uint)process.Id
            );

            if (processHandle.IsNull) {
              throw new Exception("Something wrong with the process handle. Are you running as an admin?");
            }

            byte[] payload = HostfxrPayload(
              processHandle,
              hostfxrPath,
              runtimeConfigPath,
              dllPath,
              typeName: $"{settings.Type}, {assemblyName}",
              entryMethod: settings.EntryMethod
            );

            await RemoteRunCodeAsync(processHandle, payload, cancellationToken);
          }
          finally {
            if (!processHandle.IsNull) {
              PInvoke.CloseHandle(processHandle);
            }
          }
          ctx.Status($"Injecting to process is done");
          AnsiConsole.MarkupLine("[green bold]Done[/]");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) {
          AnsiConsole.Markup("\n\n[bold yellow]Cancelled.[/]\n");
          return -2;
        }
        catch (Exception ex) {
          AnsiConsole.WriteException(ex, ExceptionFormats.ShortenEverything);
          return -1;
        }

        return 0;
      });

  }

  private byte[] HostfxrPayload(
    HANDLE processHandle,
    string hostfxrPath,
    string runtimeconfigPath,
    string dllPath,
    string typeName,
    string entryMethod)
  {
    HINSTANCE kernel32 = GetModuleHandle("kernel32.dll");
    if (kernel32.IsNull) {
      throw new Exception("Failed to get kernel32 handle");
    }

    nint loadLibrary = GetProcAddress(kernel32, "LoadLibraryW");
    if (loadLibrary == IntPtr.Zero) {
      throw new Exception("Failed to get LoadLibraryW address");
    }

    nint getProcAddress = GetProcAddress(kernel32, "GetProcAddress");
    if (getProcAddress == IntPtr.Zero) {
      throw new Exception("Failed to get GetProcAddress address");
    }
    nint hostfxrPathStrPtr = RemoteAllocateAndWrite(hostfxrPath, processHandle);
    nint hostfxrInitializeStrPtr = RemoteAllocateAndWrite("hostfxr_initialize_for_runtime_config", processHandle, Encoding.ASCII);
    nint hostfxrGetDelegateStrPtr = RemoteAllocateAndWrite("hostfxr_get_runtime_delegate", processHandle, Encoding.ASCII);
    nint hostfxrCloseStrPtr = RemoteAllocateAndWrite("hostfxr_close", processHandle, Encoding.ASCII);
    nint runtimeconfigPathStrPtr = RemoteAllocateAndWrite(runtimeconfigPath, processHandle);
    nint dllPathStrPtr = RemoteAllocateAndWrite(dllPath, processHandle);
    nint typeNameStrPtr = RemoteAllocateAndWrite(typeName, processHandle);
    nint entryMethodStrPtr = RemoteAllocateAndWrite(entryMethod, processHandle);

    Assembler asm = new(bitness: 64);
    const int stackSize = 32 + 48;
    // prolog
    asm.push(rbp);
    asm.mov(rbp, rsp);
    asm.push(rbx);          // hostfxr dll hModule
    asm.push(rdi);          // hostfxr_initialize_for_runtime_config
    asm.push(rsi);          // hostfxr_get_runtime_delegate
    asm.push(r14);          // hostfxr_close
    asm.sub(rsp, stackSize);

    // load hostfxr
    asm.mov(rcx, hostfxrPathStrPtr.ToInt64());
    asm.call((ulong)loadLibrary.ToInt64());
    // rbx contains ptr to hostfxr hModule
    asm.mov(rbx, rax);

    // search hostfxr_initialize_for_runtime_config
    asm.mov(rcx, rbx);
    asm.mov(rdx, hostfxrInitializeStrPtr.ToInt64());
    asm.call((ulong)getProcAddress.ToInt64());
    asm.mov(rdi, rax);

    // search hostfxr_get_runtime_delegate
    asm.mov(rcx, rbx);
    asm.mov(rdx, hostfxrGetDelegateStrPtr.ToInt64());
    asm.call((ulong)getProcAddress.ToInt64());
    asm.mov(rsi, rax);

    // search hostfxr_close
    asm.mov(rcx, rbx);
    asm.mov(rdx, hostfxrCloseStrPtr.ToInt64());
    asm.call((ulong)getProcAddress.ToInt64());
    asm.mov(r14, rax);

    // call hostfxr_initialize_for_runtime_config
    /// <see href="https://github.com/dotnet/runtime/blob/main/docs/design/features/host-error-codes.md" />
    AssemblerMemoryOperand hostfxrContextPtr = __[rsp + stackSize - 8];
    asm.mov(rcx, runtimeconfigPathStrPtr.ToInt64());
    asm.xor(rdx, rdx);
    asm.lea(r8, hostfxrContextPtr);
    asm.call(rdi);

    // call hostfxr_get_runtime_delegate
    AssemblerMemoryOperand runtimeDelegatePtrOffset = rsp + stackSize - 16;
    asm.mov(rcx, hostfxrContextPtr);
    asm.mov(rdx, 5);
    asm.lea(r8, __[runtimeDelegatePtrOffset]);
    asm.call(rsi);

    // call load_assembly_and_get_function_pointer
    AssemblerMemoryOperand entryPointOffset = rsp + stackSize - 24;
    AssemblerMemoryOperand arg5 = __[rsp + 32];
    AssemblerMemoryOperand arg6 = __[rsp + 40];
    asm.mov(rcx, dllPathStrPtr.ToInt64());
    asm.mov(rdx, typeNameStrPtr.ToInt64());
    asm.mov(r8, entryMethodStrPtr.ToInt64());
    asm.xor(r9, r9);
    asm.mov(arg5, r9);
    asm.lea(rax, __[entryPointOffset]);
    asm.mov(arg6, rax);
    asm.call(__qword_ptr[runtimeDelegatePtrOffset]);

    // call hostfxr_close
    asm.mov(rcx, hostfxrContextPtr);
    asm.call(r14);

    // call entryPoint
    asm.xor(rcx, rcx);
    asm.xor(rdx, rdx);
    asm.call(__qword_ptr[entryPointOffset]);

    // epilogue
    asm.add(rsp, stackSize);
    asm.pop(r14);
    asm.pop(rsi);
    asm.pop(rdi);
    asm.pop(rbx);
    asm.pop(rbp);
    asm.ret();

    using MemoryStream memoryStream = new(Math.Max(64, asm.Instructions.Count * 2));
    StreamCodeWriter codeWriter = new(memoryStream);

    InstructionBlock block = new(codeWriter, [.. asm.Instructions], 0);
    if (!BlockEncoder.TryEncode(bitness: 64, block, out string? errMsg, out _)) {
      throw new Exception("Error during Iced encode: " + errMsg);
    }
    return memoryStream.ToArray();
  }

  private static async ValueTask<Process> FindProcessByNameAsync(string processNameToInject, CancellationToken cancellationToken)
  {
    Process? process = null;
    while (!cancellationToken.IsCancellationRequested) {
      process = Array.Find(Process.GetProcesses(),
        x => string.Equals(x.ProcessName, processNameToInject, StringComparison.OrdinalIgnoreCase)
      );
      if (process != null) {
        return process;
      }
      await Task.Delay(500, cancellationToken);
    }
    cancellationToken.ThrowIfCancellationRequested();
    return process!;
  }

  /// <summary> You can use <see cref="NativeLibrary.GetExport"/> too </summary>
  private static unsafe IntPtr GetProcAddress(HINSTANCE moduleHandle, string procName)
  {
    Span<byte> ascii = Encoding.ASCII.GetBytes(procName).AsSpan();
    fixed (byte* ptrName = &ascii.GetPinnableReference()) {
      FARPROC result = PInvoke.GetProcAddress(moduleHandle, new PCSTR(ptrName));
      return (IntPtr)result;
    }
  }

  private static unsafe IntPtr RemoteAllocate(
   HANDLE processHandle,
   int size,
   VIRTUAL_ALLOCATION_TYPE allocType = VIRTUAL_ALLOCATION_TYPE.MEM_COMMIT | VIRTUAL_ALLOCATION_TYPE.MEM_RESERVE,
   PAGE_PROTECTION_FLAGS pageProtection = PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE
  )
  {
    void* ptrAllocated = PInvoke.VirtualAllocEx(
      processHandle,
      lpAddress: null,
      (nuint)size,
      allocType,
      pageProtection
    );
    nint allocated = new(ptrAllocated);
    if (allocated == IntPtr.Zero) {
      throw new Exception("Can't allocate memory");
    }
    return allocated;
  }

  private static unsafe Task RemoteRunCodeAsync(
    HANDLE processHandle,
    byte[] bytes,
    CancellationToken cancellationToken = default
  )
  {
    nint ptrCode = RemoteAllocate(processHandle, bytes.Length);
    AnsiConsole.MarkupLineInterpolated($"Write code to [blue]0x{ptrCode.ToInt64().ToString("X8", CultureInfo.InvariantCulture)}[/]");
    try {
      fixed (byte* ptrBytes = &bytes[0]) {
        if (!PInvoke.WriteProcessMemory(
              processHandle,
              ptrCode.ToPointer(),
              ptrBytes,
              (nuint)bytes.Length,
              lpNumberOfBytesWritten: null)) {
          throw new Exception("Failed to write process memory");
        }
      }

      if (PInvoke.VirtualProtectEx(
        processHandle,
        ptrCode.ToPointer(),
        (nuint)bytes.Length,
        PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ,
        lpflOldProtect: null
      )) {
        throw new Exception(
          $"Failed to call {nameof(PInvoke.VirtualProtectEx)}, GetLastError: {Marshal.GetLastWin32Error()}"
        );
      }
    }
    catch {
      FreeMemory();
      throw;
    }

    return Task.Factory.StartNew(() => {
      HANDLE threadHandle = PInvoke.CreateRemoteThread(
        processHandle,
        lpThreadAttributes: null,
        0u,
        (delegate* unmanaged[Stdcall]<void*, uint>)ptrCode,
        lpParameter: null,
        0u,
        lpThreadId: null
      );

      if (threadHandle.IsNull) {
        throw new Exception("Failed to create remote thread");
      }
      PInvoke.WaitForSingleObject(threadHandle, 0xFFFFFFFF);
    }, cancellationToken, TaskCreationOptions.RunContinuationsAsynchronously, TaskScheduler.Current
    ).ContinueWith(_ => FreeMemory(), TaskScheduler.Current);

    void FreeMemory()
    {
      if (!processHandle.IsNull && ptrCode != IntPtr.Zero) {
        PInvoke.VirtualFreeEx(processHandle, ptrCode.ToPointer(), (nuint)bytes.Length, VIRTUAL_FREE_TYPE.MEM_RELEASE);
      }
    }
  }

  /// <summary>
  /// Reads {assemblyName}.runtimeconfig.json and returns framework version
  /// </summary>
  private static async Task<string> GetFrameworkVersionAsync(
    string runtimeConfig,
    CancellationToken cancellationToken = default
  )
  {
    string json = await File.ReadAllTextAsync(runtimeConfig, cancellationToken);

    JsonDocumentOptions options = new() {
      AllowTrailingCommas = true,
      CommentHandling = JsonCommentHandling.Skip,
    };

    using var jdoc = JsonDocument.Parse(json, options);
    if (!jdoc.RootElement.TryGetProperty("runtimeOptions", out JsonElement runtimeOptionsJson)) {
      throw new Exception($"{runtimeConfig} must contain runtimeOptions");
    }

    var runtimeOptions = JsonSerializer.Deserialize<runtimeOptions>(runtimeOptionsJson.ToString())
        ?? throw new Exception($"{runtimeConfig} must contain valid json");

    return runtimeOptions.framework?.version
        ?? runtimeOptions.frameworks?.FirstOrDefault(f => f.name == "Microsoft.NETCore.App")?.version
        ?? throw new Exception($"{runtimeConfig} must contain framework version");
  }
  private sealed record runtimeOptions(
    string tfm, string rollForward, framework? framework, framework[]? frameworks);
  private sealed record framework(string name, string version);

  private static string? FindDotnetHostPath()
  {
    string dotnet = "dotnet";
    if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
      dotnet += ".exe";

    ProcessModule? mainModule = Process.GetCurrentProcess().MainModule;
    if (!string.IsNullOrEmpty(mainModule?.FileName)
      && Path.GetFileName(mainModule.FileName)!.Equals(dotnet, StringComparison.OrdinalIgnoreCase)) {
      return mainModule.FileName;
    }
    string? environmentVariable = Environment.GetEnvironmentVariable("DOTNET_ROOT");
    if (!string.IsNullOrEmpty(environmentVariable))
      return Path.Combine(environmentVariable, dotnet);

    string? paths = Environment.GetEnvironmentVariable("PATH");
    if (paths == null)
      return null;

    foreach (string path in paths.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries)) {
      string fullPath = Path.Combine(path, dotnet);
      if (File.Exists(fullPath))
        return fullPath;
    }
    return null;
  }

  /// <summary>
  /// Works on the local process memory
  /// (also can be used for shared dlls like kernel32.dll, user32.dll and ntdll.dll)
  /// </summary>
  private static unsafe HINSTANCE GetModuleHandle(string moduleName)
  {
    fixed (char* ptrName = &moduleName.GetPinnableReference()) {
      return PInvoke.GetModuleHandle(new PCWSTR(ptrName));
    }
  }

  private static unsafe IntPtr RemoteAllocateAndWrite(
    string str,
    HANDLE processHandle,
    Encoding? encoding = null)
  {
    encoding ??= Encoding.Unicode;
    byte[] byteString = encoding.GetBytes(str);
    nint ptr = RemoteAllocate(
      processHandle,
      byteString.Length,
      pageProtection: PAGE_PROTECTION_FLAGS.PAGE_READWRITE);

    fixed (byte* bytes = byteString) {
      if (!PInvoke.WriteProcessMemory(
        processHandle,
        ptr.ToPointer(),
        bytes,
        (nuint)byteString.Length,
        (nuint*)0)) {
        throw new Exception("Failed to write process memory");
      }
    }
    return ptr;
  }
}
