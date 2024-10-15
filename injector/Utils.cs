using System;
using System.IO;
using System.Threading;
using System.Windows.Forms;
using Newtonsoft.Json;

namespace injector;

public class Utils
{
    public static string GetFilePath(string title, string filter, string folder = null)
    {
        var filePath = "";
        var t = new Thread(() =>
        {
            using var openFileDialog = new OpenFileDialog();
            openFileDialog.InitialDirectory = folder ?? Environment.CurrentDirectory;
            openFileDialog.Filter = filter;
            openFileDialog.Title = title;
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                filePath = openFileDialog.FileName;
            }
        });
        t.SetApartmentState(ApartmentState.STA);
        t.Start();
        t.Join();
        return filePath;
    }

    public static Config ReadConfig(string path = "config.json")
    {
        path = Path.GetFullPath(path);
        Config cfg;

        try
        {
            cfg = JsonConvert.DeserializeObject<Config>(File.ReadAllText(path));
        }
        catch (Exception)
        {
            File.WriteAllText(path, "{}");
            cfg = new Config();
        }

        var wasChanged = false;

        // selecting file
        if (!File.Exists(cfg.ExePath))
        {
            cfg.ExePath = GetFilePath("Provide path to Anime Game Exe",
                "exe files (*.exe)|*.exe|All files (*.*)|*.*",
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles));
            wasChanged = true;
        }
        
        if (cfg.Delay < TimeSpan.FromSeconds(1))
        {
            cfg.Delay = TimeSpan.FromSeconds(15);
            wasChanged = true;
        }
        
        if (wasChanged)
            File.WriteAllText(path, JsonConvert.SerializeObject(cfg, Formatting.Indented));

        return cfg;
    }
}