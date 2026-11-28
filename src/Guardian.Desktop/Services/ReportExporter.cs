using System.Globalization;
using System.Text;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.Services;

/// <summary>Contenu d'un rapport exporté.</summary>
public sealed record ReportData(
    DateTime GeneratedAt,
    string PeriodLabel,
    ProtectionState State,
    IReadOnlyList<ScanRecord> Scans,
    IReadOnlyList<ThreatItem> Threats,
    int QuarantineCount);

/// <summary>Libellés communs à l'écran Rapports et aux fichiers exportés.</summary>
public static class ReportFormat
{
    public static string KindLabel(ScanKind kind) => kind switch
    {
        ScanKind.Full => Loc.T("Analyse complète"),
        ScanKind.Custom => Loc.T("Analyse personnalisée"),
        _ => Loc.T("Analyse rapide"),
    };

    public static string OutcomeLabel(ScanOutcome outcome) => outcome switch
    {
        ScanOutcome.Cancelled => Loc.T("Annulée"),
        ScanOutcome.Failed => Loc.T("Échec"),
        _ => Loc.T("Terminée"),
    };

    public static string StateLabel(ProtectionState state) => state switch
    {
        ProtectionState.Healthy => Loc.T("Protégé"),
        ProtectionState.Degraded => Loc.T("Protection partielle"),
        ProtectionState.OutOfDate => Loc.T("Définitions obsolètes"),
        ProtectionState.Stopped => Loc.T("Protection arrêtée"),
        _ => Loc.T("État inconnu"),
    };

    public static string RiskLabel(RiskLevel risk) => risk switch
    {
        RiskLevel.High => Loc.T("Élevé"),
        RiskLevel.Medium => Loc.T("Moyen"),
        _ => Loc.T("Faible"),
    };

    /// <summary>"12 s", "3 min 05 s" ou "1 h 02 min".</summary>
    public static string Duration(double seconds)
    {
        var total = (int)Math.Max(0, Math.Round(seconds));
        if (total < 60)
        {
            return $"{total} s";
        }

        if (total < 3600)
        {
            return $"{total / 60} min {total % 60:00} s";
        }

        return $"{total / 3600} h {total % 3600 / 60:00} min";
    }
}

/// <summary>Génère les rapports exportables (HTML autonome et CSV) à partir de l'historique.</summary>
public static class ReportExporter
{
    /// <summary>
    /// CSV de l'historique. Le séparateur est celui de la culture (point-virgule en français),
    /// pour que le fichier s'ouvre directement dans Excel.
    /// </summary>
    public static string BuildCsv(IEnumerable<ScanRecord> scans, string? separator = null)
    {
        var sep = string.IsNullOrEmpty(separator) ? CultureInfo.CurrentCulture.TextInfo.ListSeparator : separator;
        var sb = new StringBuilder();

        sb.AppendLine(string.Join(sep, new[]
        {
            Loc.T("Date"),
            Loc.T("Type"),
            Loc.T("Durée (s)"),
            Loc.T("Fichiers analysés"),
            Loc.T("Fichiers ignorés"),
            Loc.T("Menaces"),
            Loc.T("Résultat"),
        }.Select(h => Csv(h, sep))));

        foreach (var s in scans)
        {
            sb.AppendLine(string.Join(sep, new[]
            {
                Csv(s.StartedAt.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture), sep),
                Csv(ReportFormat.KindLabel(s.Kind), sep),
                Csv(Math.Round(s.DurationSeconds).ToString("0", CultureInfo.InvariantCulture), sep),
                Csv(s.FilesScanned.ToString(CultureInfo.InvariantCulture), sep),
                Csv(s.FilesSkipped.ToString(CultureInfo.InvariantCulture), sep),
                Csv(s.Threats.ToString(CultureInfo.InvariantCulture), sep),
                Csv(ReportFormat.OutcomeLabel(s.Outcome), sep),
            }));
        }

        return sb.ToString();
    }

    /// <summary>Rapport HTML autonome (aucune ressource externe, aucun script).</summary>
    public static string BuildHtml(ReportData data)
    {
        var lang = Loc.IsEnglish ? "en" : "fr";
        var totalFiles = data.Scans.Sum(s => s.FilesScanned);
        var totalThreats = data.Scans.Sum(s => s.Threats);
        var sb = new StringBuilder();

        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine($"<html lang=\"{lang}\"><head><meta charset=\"utf-8\">");
        // Les noms de fichiers viennent du disque analysé : aucune ressource ni script n'est autorisé.
        sb.AppendLine("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">");
        sb.AppendLine($"<title>{H(Loc.T("Guardian — Rapport de sécurité"))}</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:'Segoe UI',Arial,sans-serif;margin:32px;color:#10243f;background:#fff}");
        sb.AppendLine("h1{margin:0 0 4px;color:#0b4ea2}h2{margin:28px 0 8px;font-size:16px;color:#0b4ea2}");
        sb.AppendLine(".muted{color:#5a7091;font-size:13px}");
        sb.AppendLine(".stats{display:flex;gap:12px;margin:18px 0}.stat{flex:1;border:1px solid #cfdcf2;border-radius:10px;padding:12px 14px}");
        sb.AppendLine(".stat b{display:block;font-size:24px}");
        sb.AppendLine("table{border-collapse:collapse;width:100%;font-size:13px}");
        sb.AppendLine("th,td{border-bottom:1px solid #dbe5f5;padding:7px 8px;text-align:left}th{color:#5a7091;font-weight:600}");
        sb.AppendLine(".bad{color:#c62828;font-weight:600}.ok{color:#1b8a4b}.warn{color:#b26a00}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine($"<h1>{H(Loc.T("Guardian — Rapport de sécurité"))}</h1>");
        sb.AppendLine($"<div class=\"muted\">{H(Loc.T("Généré le"))} {H(data.GeneratedAt.ToString("dd/MM/yyyy HH:mm"))} — {H(data.PeriodLabel)}</div>");
        sb.AppendLine($"<div class=\"muted\">{H(Loc.T("État de la protection"))} : {H(ReportFormat.StateLabel(data.State))}</div>");

        sb.AppendLine("<div class=\"stats\">");
        Stat(sb, Loc.T("Analyses effectuées"), data.Scans.Count);
        Stat(sb, Loc.T("Fichiers analysés"), totalFiles);
        Stat(sb, Loc.T("Menaces détectées"), totalThreats);
        Stat(sb, Loc.T("En quarantaine"), data.QuarantineCount);
        sb.AppendLine("</div>");

        sb.AppendLine($"<h2>{H(Loc.T("Historique des analyses"))}</h2>");
        if (data.Scans.Count == 0)
        {
            sb.AppendLine($"<p class=\"muted\">{H(Loc.T("Aucune analyse enregistrée sur cette période."))}</p>");
        }
        else
        {
            sb.AppendLine("<table><tr>"
                + string.Concat(new[] { "Date", "Type", "Durée", "Fichiers analysés", "Menaces", "Résultat" }
                    .Select(c => $"<th>{H(Loc.T(c))}</th>")) + "</tr>");
            foreach (var s in data.Scans)
            {
                var cls = s.Outcome == ScanOutcome.Completed && s.Threats == 0 ? "ok" : s.Outcome == ScanOutcome.Cancelled ? "warn" : "bad";
                sb.AppendLine("<tr>"
                    + $"<td>{H(s.StartedAt.ToString("dd/MM/yyyy HH:mm"))}</td>"
                    + $"<td>{H(ReportFormat.KindLabel(s.Kind))}</td>"
                    + $"<td>{H(ReportFormat.Duration(s.DurationSeconds))}</td>"
                    + $"<td>{s.FilesScanned:N0}</td>"
                    + $"<td>{s.Threats}</td>"
                    + $"<td class=\"{cls}\">{H(ReportFormat.OutcomeLabel(s.Outcome))}</td></tr>");
            }

            sb.AppendLine("</table>");
        }

        sb.AppendLine($"<h2>{H(Loc.T("Menaces de la dernière analyse"))}</h2>");
        if (data.Threats.Count == 0)
        {
            sb.AppendLine($"<p class=\"muted\">{H(Loc.T("Aucune menace à afficher."))}</p>");
        }
        else
        {
            sb.AppendLine("<table><tr>"
                + string.Concat(new[] { "Nom", "Risque", "Date", "Chemin" }.Select(c => $"<th>{H(Loc.T(c))}</th>")) + "</tr>");
            foreach (var t in data.Threats)
            {
                sb.AppendLine("<tr>"
                    + $"<td>{H(t.Name)}</td>"
                    + $"<td class=\"{(t.Risk == RiskLevel.High ? "bad" : "warn")}\">{H(ReportFormat.RiskLabel(t.Risk))}</td>"
                    + $"<td>{H(t.DetectedAt.ToString("dd/MM/yyyy HH:mm"))}</td>"
                    + $"<td>{H(t.Path)}</td></tr>");
            }

            sb.AppendLine("</table>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static void Stat(StringBuilder sb, string label, int value) =>
        sb.AppendLine($"<div class=\"stat\"><b>{value:N0}</b><span class=\"muted\">{H(label)}</span></div>");

    /// <summary>
    /// Échappe le texte pour le HTML (contenu et attributs). Seuls les cinq caractères sensibles sont
    /// transformés : les accents restent lisibles dans le fichier (UTF-8 déclaré dans l'en-tête).
    /// </summary>
    private static string H(string? text) => (text ?? string.Empty)
        .Replace("&", "&amp;")
        .Replace("<", "&lt;")
        .Replace(">", "&gt;")
        .Replace("\"", "&quot;")
        .Replace("'", "&#39;");

    /// <summary>Échappe une cellule CSV et neutralise les formules (=, +, -, @) interprétées par Excel.</summary>
    private static string Csv(string value, string separator)
    {
        if (value.Length > 0 && "=+-@\t\r".IndexOf(value[0]) >= 0)
        {
            value = "'" + value;
        }

        return value.Contains('"') || value.Contains('\n') || value.Contains('\r') || value.Contains(separator)
            ? "\"" + value.Replace("\"", "\"\"") + "\""
            : value;
    }
}
