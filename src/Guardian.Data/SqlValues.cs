using System.Globalization;
using Microsoft.Data.Sqlite;

namespace Guardian.Data;

/// <summary>
/// Conversions et aides communes entre types .NET et colonnes SQLite.
/// </summary>
internal static class SqlValues
{
    private const string DateFormat = "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'";

    internal const int MaxPageSize = 1000;

    public static string ToDb(DateTimeOffset value) =>
        value.UtcDateTime.ToString(DateFormat, CultureInfo.InvariantCulture);

    public static DateTimeOffset FromDb(string value) =>
        DateTimeOffset.ParseExact(
            value,
            DateFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);

    public static string ToDb(Guid value) => value.ToString("D", CultureInfo.InvariantCulture);

    public static Guid GuidFromDb(string value) => Guid.Parse(value, CultureInfo.InvariantCulture);

    public static (int Skip, int Take) NormalizePaging(int skip, int take) =>
        (Math.Max(0, skip), Math.Clamp(take, 1, MaxPageSize));

    public static void AddParameter(this SqliteCommand command, string name, object? value)
    {
        command.Parameters.AddWithValue(name, value ?? DBNull.Value);
    }

    public static void AddParameters(this SqliteCommand command, IEnumerable<KeyValuePair<string, object?>> parameters)
    {
        foreach (var parameter in parameters)
        {
            command.AddParameter(parameter.Key, parameter.Value);
        }
    }
}
