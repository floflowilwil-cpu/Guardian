namespace Guardian.Contracts.Network;

/// <summary>
/// Protocole de transport observé pour une connexion réseau.
/// </summary>
public enum NetworkProtocol
{
    /// <summary>Protocole inconnu ou non déterminé.</summary>
    Unknown = 0,

    /// <summary>Transmission Control Protocol.</summary>
    Tcp = 1,

    /// <summary>User Datagram Protocol.</summary>
    Udp = 2,

    /// <summary>Internet Control Message Protocol.</summary>
    Icmp = 3,

    /// <summary>Autre protocole identifié mais non détaillé.</summary>
    Other = 4
}

/// <summary>
/// Sens d'une connexion ou d'une règle réseau, vu depuis la machine protégée.
/// </summary>
public enum NetworkDirection
{
    /// <summary>Sens inconnu.</summary>
    Unknown = 0,

    /// <summary>Connexion sortante.</summary>
    Outbound = 1,

    /// <summary>Connexion entrante.</summary>
    Inbound = 2
}

/// <summary>
/// Nature d'un événement réseau remonté par la surveillance.
/// </summary>
public enum NetworkEventKind
{
    /// <summary>Nature inconnue.</summary>
    Unknown = 0,

    /// <summary>Connexion observée dans l'inventaire.</summary>
    ConnectionObserved = 1,

    /// <summary>Requête DNS observée.</summary>
    DnsQuery = 2,

    /// <summary>Anomalie DNS (fréquence, volume, échecs, tunneling possible).</summary>
    DnsAnomaly = 3,

    /// <summary>Indicateur de communication de type commande et contrôle (C2), jamais une certitude seule.</summary>
    C2Indicator = 4,

    /// <summary>Anomalie dans les métadonnées TLS visibles.</summary>
    TlsMetadataAnomaly = 5,

    /// <summary>Anomalie ARP sur le réseau local (ARP spoofing possible).</summary>
    ArpAnomaly = 6,

    /// <summary>Création, expiration ou suppression d'une règle de pare-feu gérée par Guardian.</summary>
    FirewallRuleChange = 7
}

/// <summary>
/// Décision réseau appliquée à un événement, après arbitrage de la politique de sécurité.
/// </summary>
public enum NetworkDecision
{
    /// <summary>Aucune décision appliquée (simple observation).</summary>
    None = 0,

    /// <summary>Connexion autorisée.</summary>
    Allowed = 1,

    /// <summary>Utilisateur ou journal averti, sans blocage.</summary>
    Warned = 2,

    /// <summary>Blocage temporaire via une règle de pare-feu gérée par Guardian.</summary>
    TemporarilyBlocked = 3
}

/// <summary>
/// Verdict de réputation d'une adresse ou d'un domaine.
/// </summary>
public enum NetworkReputation
{
    /// <summary>Réputation inconnue (source indisponible ou entité non référencée).</summary>
    Unknown = 0,

    /// <summary>Entité connue et considérée comme sûre.</summary>
    Trusted = 1,

    /// <summary>Aucun signal défavorable connu.</summary>
    Neutral = 2,

    /// <summary>Entité suspecte.</summary>
    Suspicious = 3,

    /// <summary>Entité référencée comme malveillante.</summary>
    Malicious = 4
}
