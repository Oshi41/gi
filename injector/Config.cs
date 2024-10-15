using System;
using Microsoft.Extensions.Logging;

namespace injector;

public class Config
{
    /// <summary>
    /// Path to injected dll
    /// </summary>
    public string LibName { get; set; } = "managed.dll";
    
    /// <summary>
    /// Current log level
    /// </summary>
    public LogLevel LogLevel { get; set; } = LogLevel.Information;
    
    /// <summary>
    /// Injected exe full path
    /// </summary>
    public string ExePath { get; set; }
    
    /// <summary>
    /// Inject delay
    /// </summary>
    public TimeSpan Delay { get; set; } = TimeSpan.FromSeconds(10);
}