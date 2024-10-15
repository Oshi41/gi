using System;
using Microsoft.Extensions.Logging;

namespace injector;

public class Config
{
    public string LibName { get; set; } = "lib.dll";
    public LogLevel LogLevel { get; set; } = LogLevel.Information;
    public string ExePath { get; set; }
    public TimeSpan Delay { get; set; } = TimeSpan.FromSeconds(10);
}