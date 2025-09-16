// AuthService.Application/Options/DatabaseOptions.cs
namespace AuthService.Application.Options
{
    public class DatabaseOptions
    {
        public const string SectionName = "Database";

        public string ConnectionString { get; set; } = string.Empty;
        public int CommandTimeout { get; set; } = 30;
        public bool EnableSensitiveDataLogging { get; set; } = false;
    }
}
