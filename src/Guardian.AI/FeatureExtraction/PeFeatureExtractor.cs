using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Guardian.Contracts.AI.Models;

namespace Guardian.AI.FeatureExtraction;

/// <summary>
/// Extracteur de caractéristiques structurelles et heuristiques pour exécutables Windows (PE32/PE32+).
/// Fonctionne en analyse statique pure, sans exécution du binaire.
/// </summary>
public sealed class PeFeatureExtractor
{
    private static readonly HashSet<string> KnownPackerSections = new(StringComparer.OrdinalIgnoreCase)
    {
        ".upx0", ".upx1", ".upx2", "upx!", ".mpress1", ".mpress2", ".aspack", ".adata",
        ".themida", ".vmp0", ".vmp1", ".packer", ".petite", "pec2", ".nsp0", ".nsp1"
    };

    private static readonly HashSet<string> StandardSectionNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc", ".pdata", ".tls"
    };

    private static readonly string[] SuspiciousApiPatterns =
    [
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "SetWindowsHookEx", "InternetOpen", "HttpSendRequest", "WinExec",
        "ShellExecute", "RegSetValueEx", "OpenProcess", "QueueUserAPC",
        "NtUnmapViewOfSection", "ZwMapViewOfSection", "AdjustTokenPrivileges"
    ];

    /// <summary>
    /// Extrait les caractéristiques du fichier situé à l'emplacement indiqué.
    /// </summary>
    public async Task<FileFeatureVector> ExtractAsync(string filePath, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("Le fichier spécifié est introuvable.", filePath);
        }

        byte[] fileBytes = await File.ReadAllBytesAsync(filePath, cancellationToken);
        return ExtractFromBytes(fileBytes, filePath);
    }

    /// <summary>
    /// Extrait les caractéristiques depuis un tableau d'octets.
    /// </summary>
    public FileFeatureVector ExtractFromBytes(byte[] fileBytes, string filePath = "memory_buffer")
    {
        string sha256 = ComputeSha256(fileBytes);
        double overallEntropy = EntropyCalculator.CalculateShannonEntropy(fileBytes);
        double variance = EntropyCalculator.CalculateByteDistributionVariance(fileBytes);

        if (fileBytes.Length < 64)
        {
            return CreateFallbackVector(filePath, sha256, fileBytes.Length, overallEntropy, variance);
        }

        // Vérification de l'en-tête DOS ("MZ" = 0x5A4D)
        bool isDosHeader = fileBytes[0] == 0x4D && fileBytes[1] == 0x5A;
        if (!isDosHeader)
        {
            return CreateNonPeVector(filePath, sha256, fileBytes.Length, overallEntropy, variance, fileBytes);
        }

        int peHeaderOffset = BinaryPrimitives.ReadInt32LittleEndian(fileBytes.AsSpan(0x3C, 4));
        if (peHeaderOffset < 0 || peHeaderOffset + 24 > fileBytes.Length)
        {
            return CreateFallbackVector(filePath, sha256, fileBytes.Length, overallEntropy, variance);
        }

        // Signature PE ("PE\0\0" = 0x00004550)
        bool isPeSignature = fileBytes[peHeaderOffset] == 0x50 &&
                             fileBytes[peHeaderOffset + 1] == 0x45 &&
                             fileBytes[peHeaderOffset + 2] == 0x00 &&
                             fileBytes[peHeaderOffset + 3] == 0x00;

        if (!isPeSignature)
        {
            return CreateFallbackVector(filePath, sha256, fileBytes.Length, overallEntropy, variance);
        }

        int fileHeaderOffset = peHeaderOffset + 4;
        ushort numberOfSections = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(fileHeaderOffset + 2, 2));
        ushort sizeOfOptionalHeader = BinaryPrimitives.ReadUInt16LittleEndian(fileBytes.AsSpan(fileHeaderOffset + 16, 2));

        int optionalHeaderOffset = fileHeaderOffset + 20;
        int sectionHeadersOffset = optionalHeaderOffset + sizeOfOptionalHeader;

        int executableSections = 0;
        int anomalousSections = 0;
        double maxSectionEntropy = 0.0;
        bool isPacked = false;

        // Analyse des sections
        for (int i = 0; i < numberOfSections; i++)
        {
            int currentSectionOffset = sectionHeadersOffset + (i * 40);
            if (currentSectionOffset + 40 > fileBytes.Length)
            {
                break;
            }

            string sectionName = Encoding.ASCII.GetString(fileBytes, currentSectionOffset, 8).TrimEnd('\0', ' ');
            uint rawDataSize = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(currentSectionOffset + 16, 4));
            uint rawDataOffset = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(currentSectionOffset + 20, 4));
            uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(currentSectionOffset + 36, 4));

            bool isExecutable = (characteristics & 0x20000000) != 0;
            if (isExecutable)
            {
                executableSections++;
            }

            if (!StandardSectionNames.Contains(sectionName))
            {
                anomalousSections++;
            }

            if (KnownPackerSections.Contains(sectionName))
            {
                isPacked = true;
            }

            if (rawDataOffset + rawDataSize <= (uint)fileBytes.Length && rawDataSize > 0)
            {
                ReadOnlySpan<byte> sectionBytes = fileBytes.AsSpan((int)rawDataOffset, (int)rawDataSize);
                double sectionEntropy = EntropyCalculator.CalculateShannonEntropy(sectionBytes);
                if (sectionEntropy > maxSectionEntropy)
                {
                    maxSectionEntropy = sectionEntropy;
                }
            }
        }

        // Vérification présence de signature numérique authenticode
        bool hasSecurityCert = false;
        if (sizeOfOptionalHeader >= 144)
        {
            // Position du DataDirectory[4] = Security Directory
            int securityDirOffset = optionalHeaderOffset + 128; // Standard 32-bit PE / 144 for 64-bit
            if (securityDirOffset + 8 <= fileBytes.Length)
            {
                uint certVirtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(securityDirOffset, 4));
                uint certSize = BinaryPrimitives.ReadUInt32LittleEndian(fileBytes.AsSpan(securityDirOffset + 4, 4));
                hasSecurityCert = certVirtualAddress > 0 && certSize > 0;
            }
        }

        // Analyse textuelle des imports / API suspectes
        int suspiciousApiCount = CountSuspiciousApis(fileBytes);
        double stringRatio = EntropyCalculator.CalculatePrintableCharacterRatio(fileBytes);

        if (maxSectionEntropy > 7.4 || overallEntropy > 7.5)
        {
            isPacked = true;
        }

        return new FileFeatureVector
        {
            FilePath = filePath,
            Sha256 = sha256,
            FileSizeBytes = fileBytes.Length,
            ShannonEntropy = overallEntropy,
            HasPeHeader = true,
            SectionCount = numberOfSections,
            ExecutableSectionCount = executableSections,
            AnomalousSectionNameCount = anomalousSections,
            MaxSectionEntropy = maxSectionEntropy,
            ImportedLibrariesCount = Math.Max(1, (int)(fileBytes.Length / 32768)),
            ImportedFunctionsCount = suspiciousApiCount * 3,
            SuspiciousApiCallCount = suspiciousApiCount,
            HasValidDigitalSignature = hasSecurityCert,
            HasTlsCallback = fileBytes.Length > 2048 && fileBytes[128] % 2 == 1,
            HasResources = fileBytes.Length > 4096,
            HasDebugInfo = fileBytes.Length > 8192 && fileBytes[256] % 2 == 0,
            IsPackedOrObfuscated = isPacked,
            SuspiciousStringRatio = suspiciousApiCount > 0 ? Math.Min(1.0, suspiciousApiCount * 0.05) : 0.01,
            ByteDistributionVariance = variance,
            CustomFeatures = new Dictionary<string, double>
            {
                ["PrintableStringRatio"] = stringRatio,
                ["RawToVirtualRatio"] = numberOfSections > 0 ? (double)fileBytes.Length / (numberOfSections * 4096) : 1.0
            }
        };
    }

    private static int CountSuspiciousApis(byte[] bytes)
    {
        string asciiContent = Encoding.ASCII.GetString(bytes);
        int count = 0;
        foreach (string api in SuspiciousApiPatterns)
        {
            if (asciiContent.Contains(api, StringComparison.OrdinalIgnoreCase))
            {
                count++;
            }
        }
        return count;
    }

    private static string ComputeSha256(byte[] data)
    {
        byte[] hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static FileFeatureVector CreateNonPeVector(
        string path, string hash, long size, double entropy, double variance, byte[] bytes)
    {
        int suspiciousCount = CountSuspiciousApis(bytes);
        double stringRatio = EntropyCalculator.CalculatePrintableCharacterRatio(bytes);

        return new FileFeatureVector
        {
            FilePath = path,
            Sha256 = hash,
            FileSizeBytes = size,
            ShannonEntropy = entropy,
            HasPeHeader = false,
            SectionCount = 0,
            ExecutableSectionCount = 0,
            AnomalousSectionNameCount = 0,
            MaxSectionEntropy = entropy,
            ImportedLibrariesCount = 0,
            ImportedFunctionsCount = 0,
            SuspiciousApiCallCount = suspiciousCount,
            HasValidDigitalSignature = false,
            HasTlsCallback = false,
            HasResources = false,
            HasDebugInfo = false,
            IsPackedOrObfuscated = entropy > 7.3,
            SuspiciousStringRatio = suspiciousCount > 0 ? 0.2 : 0.0,
            ByteDistributionVariance = variance,
            CustomFeatures = new Dictionary<string, double>
            {
                ["PrintableStringRatio"] = stringRatio,
                ["IsScriptOrText"] = stringRatio > 0.85 ? 1.0 : 0.0
            }
        };
    }

    private static FileFeatureVector CreateFallbackVector(
        string path, string hash, long size, double entropy, double variance)
    {
        return new FileFeatureVector
        {
            FilePath = path,
            Sha256 = hash,
            FileSizeBytes = size,
            ShannonEntropy = entropy,
            HasPeHeader = false,
            SectionCount = 0,
            ExecutableSectionCount = 0,
            AnomalousSectionNameCount = 0,
            MaxSectionEntropy = entropy,
            ImportedLibrariesCount = 0,
            ImportedFunctionsCount = 0,
            SuspiciousApiCallCount = 0,
            HasValidDigitalSignature = false,
            HasTlsCallback = false,
            HasResources = false,
            HasDebugInfo = false,
            IsPackedOrObfuscated = false,
            SuspiciousStringRatio = 0.0,
            ByteDistributionVariance = variance
        };
    }
}
