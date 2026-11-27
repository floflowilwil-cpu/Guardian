using System.ComponentModel;
using System.Globalization;
using System.Windows.Data;
using System.Windows.Markup;

namespace Guardian.Desktop.Infrastructure;

/// <summary>
/// Localisation FR/EN. Le texte français sert de clé : sans traduction, il est affiché tel quel.
/// Le changement de langue est immédiat (les liaisons {loc:Loc '...'} se rafraîchissent seules).
/// </summary>
public sealed class Loc : INotifyPropertyChanged
{
    public static Loc Instance { get; } = new();

    public static bool IsEnglish { get; private set; }

    /// <summary>Levée après chaque changement de langue (pour recalculer les textes des ViewModels).</summary>
    public static event Action? LanguageChanged;

    public event PropertyChangedEventHandler? PropertyChanged;

    public int Revision { get; private set; }

    public static void SetLanguage(string? language)
    {
        var english = string.Equals(language, "English", StringComparison.OrdinalIgnoreCase);
        if (english == IsEnglish)
        {
            return;
        }

        IsEnglish = english;
        Instance.Revision++;
        Instance.PropertyChanged?.Invoke(Instance, new PropertyChangedEventArgs(nameof(Revision)));
        LanguageChanged?.Invoke();
    }

    /// <summary>Traduit un texte français (retourne le texte d'origine si aucune traduction n'existe).</summary>
    public static string T(string french) =>
        IsEnglish && English.TryGetValue(french, out var value) ? value : french;

    private static readonly Dictionary<string, string> English = new()
    {
        ["Annuler"] = "Cancel",
        ["Automatique"] = "Automatic",
        ["Clair"] = "Light",
        ["Démarrer l'analyse"] = "Start scan",
        ["Mettre en quarantaine"] = "Quarantine",
        ["Restaurer"] = "Restore",
        ["Sombre"] = "Dark",
        ["Supprimer"] = "Delete",
        ["Voir les détails"] = "View details",
        ["Activité récente"] = "Recent activity",
        ["Activité réseau"] = "Network activity",
        ["Analyse complète"] = "Full scan",
        ["Analyse en cours..."] = "Scan in progress...",
        ["Analyse personnalisée"] = "Custom scan",
        ["Analyse rapide"] = "Quick scan",
        ["Apparence"] = "Appearance",
        ["Assistant Guardian IA"] = "Guardian AI Assistant",
        ["Aucune donnée ne quitte l'appareil."] = "No data leaves the device.",
        ["Aucune donnée réseau disponible."] = "No network data available.",
        ["Aucune menace à afficher."] = "No threats to display.",
        ["Centre d'analyse"] = "Scan center",
        ["Centre des menaces"] = "Threat center",
        ["Cette page sera disponible dans une prochaine version."] = "This page will be available in a future version.",
        ["Choisissez votre type d'analyse"] = "Choose your scan type",
        ["Compatible Windows 10 / 11"] = "Compatible with Windows 10 / 11",
        ["Confidentialité et notifications"] = "Privacy and notifications",
        ["Connexions actives"] = "Active connections",
        ["Connexions suspectes"] = "Suspicious connections",
        ["Des performances optimisées"] = "Optimized performance",
        ["Définitions"] = "Definitions",
        ["Détails de la menace sélectionnée"] = "Selected threat details",
        ["Détecter. Protéger. Réagir."] = "Detect. Protect. Respond.",
        ["ESPACE DE SÉCURITÉ"] = "SECURITY SPACE",
        ["En quarantaine"] = "In quarantine",
        ["Fichiers sensibles et zones critiques"] = "Sensitive files and critical areas",
        ["IA locale"] = "Local AI",
        ["Lancer un scan"] = "Start a scan",
        ["Langue"] = "Language",
        ["Les fichiers isolés ne peuvent pas être exécutés."] = "Isolated files cannot be executed.",
        ["Les fichiers suspects sont isolés et sécurisés."] = "Suspicious files are isolated and secured.",
        ["Menaces bloquées"] = "Blocked threats",
        ["Mises à jour"] = "Updates",
        ["Mode hors ligne"] = "Offline mode",
        ["Mode silencieux"] = "Silent mode",
        ["Moteur IA"] = "AI engine",
        ["Niveau de risque : "] = "Risk level: ",
        ["Nom"] = "Name",
        ["Paramètres"] = "Settings",
        ["Principales destinations"] = "Top destinations",
        ["Protection active"] = "Active protection",
        ["Quarantaine sécurisée"] = "Secure quarantine",
        ["Quarantaine"] = "Quarantine",
        ["Rapports"] = "Reports",
        ["Risque"] = "Risk",
        ["Réduit les notifications sans désactiver les protections."] = "Reduces notifications without disabling protections.",
        ["Thème de l'application"] = "Application theme",
        ["Tout votre système"] = "Your entire system",
        ["Une protection complète"] = "Complete protection",
        ["Une sécurité complète, intelligente et transparente."] = "Complete, intelligent and transparent security.",
        ["Votre vie privée respectée"] = "Your privacy respected",
        ["Vue d'ensemble"] = "Overview",
        ["État des moteurs"] = "Engine status",
        ["Événements"] = "Events",
        ["•  Votre allié sécurité sur Windows"] = "•  Your security ally on Windows",
        ["Agrandir"] = "Maximize",
        ["Envoyer"] = "Send",
        ["Fermer"] = "Close",
        ["Réduire"] = "Minimize",
        ["Accueil"] = "Home",
        ["Analyse"] = "Scan",
        ["Menaces"] = "Threats",
        ["Réseau"] = "Network",
        ["Système"] = "System",
        ["IA Assistant"] = "AI Assistant",
        ["Surveillance système"] = "System monitoring",
        ["Historique et rapports"] = "History and reports",
        ["Sélectionnez vos dossiers"] = "Select your folders",
        ["Protégé"] = "Protected",
        ["Protection partielle"] = "Partial protection",
        ["Définitions obsolètes"] = "Outdated definitions",
        ["Protection arrêtée"] = "Protection stopped",
        ["État inconnu"] = "Unknown state",
        ["Votre appareil est sécurisé"] = "Your device is secure",
        ["Un ou plusieurs moteurs sont dégradés"] = "One or more engines are degraded",
        ["Mettez à jour les définitions"] = "Update the definitions",
        ["Le service Guardian est arrêté"] = "The Guardian service is stopped",
        ["En attente du service Guardian"] = "Waiting for the Guardian service",
        ["Inconnu"] = "Unknown",
        ["Actif"] = "Active",
        ["Inactif"] = "Inactive",
        ["À jour"] = "Up to date",
        ["Obsolètes"] = "Outdated",
        ["Active"] = "Active",
        ["Inactive"] = "Inactive",
        ["Aucune donnée : le service Guardian ne répond pas."] = "No data: the Guardian service is not responding.",
        ["Aucune menace détectée récemment"] = "No threat detected recently",
        ["menace(s) détectée(s) récemment"] = "threat(s) detected recently",
        ["Protection en temps réel"] = "Real-time protection",
        ["Activée et opérationnelle"] = "Enabled and operational",
        ["Dégradée : au moins un moteur ne répond pas normalement"] = "Degraded: at least one engine is not responding normally",
        ["Opérationnelle, définitions à mettre à jour"] = "Operational, definitions need updating",
        ["Arrêtée"] = "Stopped",
        ["Dégradée"] = "Degraded",
        ["Obsolète"] = "Outdated",
        ["Inconnue"] = "Unknown",
        ["Aucune menace détectée. Dernière vérification :"] = "No threat detected. Last check:",
        ["menace(s) détectée(s). Dernière vérification :"] = "threat(s) detected. Last check:",
        ["inconnue"] = "unknown",
        ["aujourd'hui à"] = "today at",
        ["Élevé"] = "High",
        ["Moyen"] = "Medium",
        ["Faible"] = "Low",
        ["Demande de mise en quarantaine envoyée au service."] = "Quarantine request sent to the service.",
        ["Le service n'a pas pu traiter la demande."] = "The service could not process the request.",
        ["Restauration"] = "Restoration",
        ["Suppression"] = "Deletion",
        ["demandée au service."] = "requested from the service.",
        ["Éléments en quarantaine"] = "Quarantined items",
        ["Sélectionnez au moins un élément."] = "Select at least one item.",
        ["Supprimer définitivement {0} élément(s) ? Cette action est irréversible."] = "Permanently delete {0} item(s)? This action cannot be undone.",
        ["Bonjour ! Je suis Guardian IA. Comment puis-je vous aider ?"] = "Hello! I'm Guardian AI. How can I help you?",
        ["Pourquoi ce fichier est-il bloqué ?"] = "Why is this file blocked?",
        ["Voir les menaces liées"] = "View related threats",
        ["Analyser un fichier"] = "Analyze a file",
        ["L'assistant local n'est pas joignable : le service Guardian ne répond pas."] = "The local assistant is unreachable: the Guardian service is not responding.",
        ["Impossible de lancer l'analyse : le service Guardian ne répond pas."] = "Unable to start the scan: the Guardian service is not responding.",
        ["Analyse annulée."] = "Scan cancelled.",
        ["Analyse terminée : {0} fichier(s) analysé(s), {1} ignoré(s), {2} menace(s)."] = "Scan complete: {0} file(s) scanned, {1} skipped, {2} threat(s).",
        ["L'analyse a échoué : {0}"] = "The scan failed: {0}",
        ["Fichiers analysés"] = "Files scanned",
        ["en cours..."] = "in progress...",
        ["Tous les moteurs sont opérationnels"] = "All engines are operational",
        ["Certains moteurs sont dégradés"] = "Some engines are degraded",
        ["Des définitions sont obsolètes"] = "Some definitions are outdated",
        ["État des moteurs inconnu"] = "Engine status unknown",
        ["Analyse des fichiers"] = "File scanning",
        ["Protection réseau"] = "Network protection",
        ["Protection comportementale"] = "Behavioral protection",
        ["Autres"] = "Others",
    };
}

/// <summary>Extension XAML : <c>Text="{loc:Loc 'Analyse rapide'}"</c>.</summary>
[MarkupExtensionReturnType(typeof(string))]
public sealed class LocExtension : MarkupExtension
{
    public LocExtension()
    {
    }

    public LocExtension(string key) => Key = key;

    public string Key { get; set; } = string.Empty;

    public override object ProvideValue(IServiceProvider serviceProvider)
    {
        var binding = new Binding(nameof(Loc.Revision))
        {
            Source = Loc.Instance,
            Mode = BindingMode.OneWay,
            Converter = LocConverter.Instance,
            ConverterParameter = Key,
        };
        return binding.ProvideValue(serviceProvider);
    }
}

public sealed class LocConverter : IValueConverter
{
    public static LocConverter Instance { get; } = new();

    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        Loc.T(parameter as string ?? string.Empty);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
