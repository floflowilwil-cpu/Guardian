-- Guardian : schéma initial (v1)
-- Les dates sont stockées en texte UTC ISO 8601 (yyyy-MM-ddTHH:mm:ss.fffffffZ), triables lexicalement.
-- Les identifiants Guid sont stockés en texte (format D).
-- Aucune colonne ne doit contenir de mot de passe, secret, clé privée ni frappe clavier.

CREATE TABLE ScanJobs (
    ScanJobId      TEXT    NOT NULL PRIMARY KEY,
    Scope          INTEGER NOT NULL,
    CustomPath     TEXT    NULL,
    StartedAtUtc   TEXT    NOT NULL,
    CompletedAtUtc TEXT    NULL,
    Status         INTEGER NOT NULL DEFAULT 0,
    FilesScanned   INTEGER NOT NULL DEFAULT 0,
    FilesSkipped   INTEGER NOT NULL DEFAULT 0,
    ThreatsFound   INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE ScanItems (
    ScanItemId   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    ScanJobId    TEXT    NOT NULL REFERENCES ScanJobs(ScanJobId) ON DELETE CASCADE,
    FilePath     TEXT    NOT NULL,
    Sha256       TEXT    NULL,
    Verdict      INTEGER NOT NULL,
    Skipped      INTEGER NOT NULL DEFAULT 0,
    ScannedAtUtc TEXT    NOT NULL
) STRICT;

CREATE INDEX IX_ScanItems_ScanJobId ON ScanItems(ScanJobId);

CREATE TABLE Threats (
    ThreatId        TEXT    NOT NULL PRIMARY KEY,
    DetectedAtUtc   TEXT    NOT NULL,
    UpdatedAtUtc    TEXT    NOT NULL,
    DisplayName     TEXT    NOT NULL,
    Verdict         INTEGER NOT NULL,
    RiskScore       INTEGER NOT NULL CHECK (RiskScore BETWEEN 0 AND 100),
    Status          INTEGER NOT NULL,
    DetectionSource TEXT    NOT NULL,
    FilePath        TEXT    NULL,
    Sha256          TEXT    NULL
) STRICT;

CREATE INDEX IX_Threats_DetectedAtUtc ON Threats(DetectedAtUtc);
CREATE INDEX IX_Threats_Status        ON Threats(Status, UpdatedAtUtc);
CREATE INDEX IX_Threats_Sha256        ON Threats(Sha256);

CREATE TABLE ThreatEvidence (
    EvidenceId    TEXT NOT NULL PRIMARY KEY,
    ThreatId      TEXT NOT NULL REFERENCES Threats(ThreatId) ON DELETE CASCADE,
    ObservedAtUtc TEXT NOT NULL,
    Kind          TEXT NOT NULL,
    Description   TEXT NOT NULL,
    MetadataJson  TEXT NOT NULL DEFAULT '{}'
) STRICT;

CREATE INDEX IX_ThreatEvidence_ThreatId ON ThreatEvidence(ThreatId);

CREATE TABLE QuarantineItems (
    QuarantineId     TEXT    NOT NULL PRIMARY KEY,
    ThreatId         TEXT    NULL REFERENCES Threats(ThreatId) ON DELETE SET NULL,
    OriginalPath     TEXT    NOT NULL,
    StoredName       TEXT    NOT NULL,
    Sha256           TEXT    NOT NULL,
    QuarantinedAtUtc TEXT    NOT NULL,
    RestoredAtUtc    TEXT    NULL,
    Status           INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE TABLE SystemEvents (
    EventId      TEXT    NOT NULL PRIMARY KEY,
    TimestampUtc TEXT    NOT NULL,
    Category     INTEGER NOT NULL,
    Severity     INTEGER NOT NULL,
    Source       TEXT    NOT NULL,
    ProcessId    INTEGER NULL,
    Summary      TEXT    NOT NULL,
    PayloadJson  TEXT    NOT NULL
) STRICT;

CREATE INDEX IX_SystemEvents_TimestampUtc ON SystemEvents(TimestampUtc);
CREATE INDEX IX_SystemEvents_Severity     ON SystemEvents(Severity, TimestampUtc);

CREATE TABLE NetworkEvents (
    EventId       TEXT    NOT NULL PRIMARY KEY,
    TimestampUtc  TEXT    NOT NULL,
    Kind          INTEGER NOT NULL,
    Severity      INTEGER NOT NULL,
    Decision      INTEGER NOT NULL,
    AppliedRuleId TEXT    NULL,
    ProcessId     INTEGER NULL,
    RemoteAddress TEXT    NULL,
    Domain        TEXT    NULL,
    Summary       TEXT    NOT NULL,
    PayloadJson   TEXT    NOT NULL
) STRICT;

CREATE INDEX IX_NetworkEvents_TimestampUtc ON NetworkEvents(TimestampUtc);
CREATE INDEX IX_NetworkEvents_Severity     ON NetworkEvents(Severity, TimestampUtc);
CREATE INDEX IX_NetworkEvents_Domain       ON NetworkEvents(Domain);

CREATE TABLE PolicyDecisions (
    DecisionId     TEXT    NOT NULL PRIMARY KEY,
    DecidedAtUtc   TEXT    NOT NULL,
    Subject        TEXT    NOT NULL,
    Action         TEXT    NOT NULL,
    AutonomyLevel  INTEGER NOT NULL DEFAULT 0,
    Outcome        TEXT    NOT NULL,
    Reason         TEXT    NULL
) STRICT;

CREATE INDEX IX_PolicyDecisions_DecidedAtUtc ON PolicyDecisions(DecidedAtUtc);

CREATE TABLE Signatures (
    SignatureId   TEXT NOT NULL PRIMARY KEY,
    Sha256        TEXT NOT NULL UNIQUE,
    Name          TEXT NOT NULL,
    Family        TEXT NULL,
    AddedAtUtc    TEXT NOT NULL,
    SourceVersion TEXT NULL
) STRICT;

CREATE TABLE ModelVersions (
    ModelId        TEXT    NOT NULL,
    Version        TEXT    NOT NULL,
    Sha256         TEXT    NOT NULL,
    InstalledAtUtc TEXT    NOT NULL,
    IsActive       INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ModelId, Version)
) STRICT;

CREATE TABLE UpdateHistory (
    EntryId         TEXT    NOT NULL PRIMARY KEY,
    TimestampUtc    TEXT    NOT NULL,
    ComponentKind   INTEGER NOT NULL,
    FromVersion     TEXT    NULL,
    ToVersion       TEXT    NOT NULL,
    Status          INTEGER NOT NULL,
    RejectionReason INTEGER NOT NULL DEFAULT 0
) STRICT;

CREATE INDEX IX_UpdateHistory_TimestampUtc ON UpdateHistory(TimestampUtc);

CREATE TABLE Exclusions (
    ExclusionId  TEXT NOT NULL PRIMARY KEY,
    Kind         TEXT NOT NULL,
    ExclusionValue TEXT NOT NULL,
    CreatedAtUtc TEXT NOT NULL,
    Reason       TEXT NULL
) STRICT;

-- Réglages non sensibles uniquement : aucun secret ni jeton dans cette table.
CREATE TABLE Settings (
    SettingKey   TEXT NOT NULL PRIMARY KEY,
    SettingValue TEXT NOT NULL,
    UpdatedAtUtc TEXT NOT NULL
) STRICT;

CREATE TABLE AuditEvents (
    EventId      TEXT    NOT NULL PRIMARY KEY,
    TimestampUtc TEXT    NOT NULL,
    Category     TEXT    NOT NULL,
    Action       TEXT    NOT NULL,
    Actor        TEXT    NOT NULL,
    Target       TEXT    NOT NULL,
    Succeeded    INTEGER NOT NULL,
    Details      TEXT    NULL
) STRICT;

CREATE INDEX IX_AuditEvents_TimestampUtc ON AuditEvents(TimestampUtc);

-- Journal d'audit en ajout seul : toute modification est refusée.
-- La suppression n'est possible que par la purge de rétention explicite.
CREATE TRIGGER TR_AuditEvents_NoUpdate
BEFORE UPDATE ON AuditEvents
BEGIN
    SELECT RAISE(ABORT, 'AuditEvents est en ajout seul.');
END;

CREATE TABLE HealthChecks (
    HealthCheckId INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    TimestampUtc  TEXT    NOT NULL,
    Component     TEXT    NOT NULL,
    Status        INTEGER NOT NULL,
    Summary       TEXT    NOT NULL
) STRICT;

CREATE INDEX IX_HealthChecks_TimestampUtc ON HealthChecks(TimestampUtc);

CREATE TABLE SandboxRuns (
    SandboxRunId   TEXT    NOT NULL PRIMARY KEY,
    ThreatId       TEXT    NULL REFERENCES Threats(ThreatId) ON DELETE SET NULL,
    StartedAtUtc   TEXT    NOT NULL,
    CompletedAtUtc TEXT    NULL,
    Status         INTEGER NOT NULL DEFAULT 0,
    Verdict        INTEGER NULL
) STRICT;
