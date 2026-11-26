using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using Guardian.Contracts.Common;
using Guardian.Contracts.System;

namespace Guardian.Windows.Security;

/// <summary>
/// Vérifie l'intégrité SHA-256 et la confiance Authenticode (<c>WinVerifyTrust</c> et catalogues Windows) sans API obsolète.
/// </summary>
public sealed class WindowsAuthenticodeVerifier : IWindowsAuthenticodeVerifier
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdChoiceCatalog = 2;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x00000010;
    private const uint WtdCacheOnlyUrlRetrieval = 0x00001000;

    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const uint CertQueryObjectFile = 0x00000001;
    private const uint CertQueryContentFlagPkcs7SignedEmbed = 1 << 10;
    private const uint CertQueryFormatFlagBinary = 1 << 1;
    private const uint CertNameSimpleDisplayType = 4;

    private static readonly Guid WinTrustActionGenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    /// <inheritdoc />
    public async Task<FileIntegrityResultDto> VerifyFileAsync(
        string filePath,
        string? expectedSha256 = null,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new FileIntegrityResultDto(
                FilePath: filePath ?? string.Empty,
                Exists: false,
                Sha256: null,
                ExpectedHashMatched: expectedSha256 is null ? null : false,
                IsAuthenticodeSigned: false,
                IsSignatureValid: false,
                SignerSubject: null,
                TrustStatusCode: null,
                Availability: FeatureAvailabilityStatus.Available,
                Summary: "Target file does not exist.");
        }

        byte[] actualHash;
        await using (var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 65536,
            useAsync: true))
        {
            actualHash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        }

        var actualHex = Convert.ToHexString(actualHash).ToLowerInvariant();
        bool? hashMatched = null;
        if (!string.IsNullOrWhiteSpace(expectedSha256))
        {
            hashMatched = TryFixedTimeCompareSha256(actualHash, expectedSha256);
        }

        if (!OperatingSystem.IsWindows())
        {
            return new FileIntegrityResultDto(
                FilePath: filePath,
                Exists: true,
                Sha256: actualHex,
                ExpectedHashMatched: hashMatched,
                IsAuthenticodeSigned: false,
                IsSignatureValid: false,
                SignerSubject: null,
                TrustStatusCode: null,
                Availability: FeatureAvailabilityStatus.Unavailable,
                Summary: "SHA-256 computed; Authenticode verification requires Windows.");
        }

        var (isSigned, isValid, signerSubject, trustStatusCode) = VerifyAuthenticodeWindows(filePath);
        var summary = BuildSummary(hashMatched, isSigned, isValid, trustStatusCode);

        return new FileIntegrityResultDto(
            FilePath: filePath,
            Exists: true,
            Sha256: actualHex,
            ExpectedHashMatched: hashMatched,
            IsAuthenticodeSigned: isSigned,
            IsSignatureValid: isValid,
            SignerSubject: signerSubject,
            TrustStatusCode: trustStatusCode,
            Availability: FeatureAvailabilityStatus.Available,
            Summary: summary);
    }

    private static bool TryFixedTimeCompareSha256(byte[] actualHash, string expectedSha256)
    {
        try
        {
            var expectedBytes = Convert.FromHexString(expectedSha256.Trim());
            if (expectedBytes.Length != actualHash.Length)
            {
                return false;
            }

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedBytes);
        }
        catch (FormatException)
        {
            return false;
        }
    }

    private static string BuildSummary(bool? hashMatched, bool isSigned, bool isValid, int statusCode)
    {
        if (hashMatched == false)
        {
            return "File SHA-256 does not match the expected hash.";
        }

        if (isValid)
        {
            return "File integrity verified and Authenticode signature is valid.";
        }

        if (!isSigned)
        {
            return "File is not Authenticode signed.";
        }

        return $"File Authenticode verification failed (status: 0x{statusCode:X8}).";
    }

    [SupportedOSPlatform("windows")]
    private static (bool IsSigned, bool IsValid, string? SignerSubject, int StatusCode) VerifyAuthenticodeWindows(string filePath)
    {
        var embeddedStatus = VerifyEmbeddedSignature(filePath);
        if (embeddedStatus == 0)
        {
            var signer = TryExtractEmbeddedSignerSubject(filePath);
            return (true, true, signer, embeddedStatus);
        }

        if (embeddedStatus == TrustENoSignature)
        {
            var catalogResult = VerifyViaCatalog(filePath);
            if (catalogResult.HasValue)
            {
                return catalogResult.Value;
            }

            return (false, false, null, embeddedStatus);
        }

        var embeddedSigner = TryExtractEmbeddedSignerSubject(filePath);
        return (embeddedSigner is not null, false, embeddedSigner, embeddedStatus);
    }

    [SupportedOSPlatform("windows")]
    private static int VerifyEmbeddedSignature(string filePath)
    {
        var filePathPtr = Marshal.StringToCoTaskMemUni(filePath);
        var fileInfoPtr = IntPtr.Zero;
        try
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = checked((uint)Marshal.SizeOf<WINTRUST_FILE_INFO>()),
                pcwszFilePath = filePathPtr,
                hFile = IntPtr.Zero,
                pgKnownSubject = IntPtr.Zero
            };

            fileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_FILE_INFO>());
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, fDeleteOld: false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = checked((uint)Marshal.SizeOf<WINTRUST_DATA>()),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceFile,
                pInfoStruct = fileInfoPtr,
                dwStateAction = WtdStateActionVerify,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            var action = WinTrustActionGenericVerifyV2;
            var status = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            trustData.dwStateAction = WtdStateActionClose;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            return status;
        }
        finally
        {
            if (fileInfoPtr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WINTRUST_FILE_INFO>(fileInfoPtr);
                Marshal.FreeCoTaskMem(fileInfoPtr);
            }

            if (filePathPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(filePathPtr);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static (bool IsSigned, bool IsValid, string? SignerSubject, int StatusCode)? VerifyViaCatalog(string filePath)
    {
        foreach (var algorithm in new[] { "SHA256", "SHA1" })
        {
            if (!CryptCATAdminAcquireContext2(out var hCatAdmin, IntPtr.Zero, algorithm, IntPtr.Zero, 0))
            {
                continue;
            }

            try
            {
                using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                var safeHandle = stream.SafeFileHandle;
                var addRefSuccess = false;
                try
                {
                    safeHandle.DangerousAddRef(ref addRefSuccess);
                    var rawHandle = safeHandle.DangerousGetHandle();

                    uint hashSize = 0;
                    _ = CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, rawHandle, ref hashSize, IntPtr.Zero, 0);
                    if (hashSize == 0)
                    {
                        continue;
                    }

                    var hashPtr = Marshal.AllocCoTaskMem(checked((int)hashSize));
                    try
                    {
                        if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, rawHandle, ref hashSize, hashPtr, 0))
                        {
                            continue;
                        }

                        var hashBytes = new byte[hashSize];
                        Marshal.Copy(hashPtr, hashBytes, 0, checked((int)hashSize));
                        var memberTag = Convert.ToHexString(hashBytes);

                        var prevCatInfo = IntPtr.Zero;
                        var hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, hashPtr, hashSize, 0, ref prevCatInfo);
                        if (hCatInfo == IntPtr.Zero)
                        {
                            continue;
                        }

                        try
                        {
                            var catInfo = new CATALOG_INFO
                            {
                                cbStruct = checked((uint)Marshal.SizeOf<CATALOG_INFO>()),
                                wszCatalogFile = string.Empty
                            };

                            if (!CryptCATCatalogInfoFromContext(hCatInfo, ref catInfo, 0) ||
                                string.IsNullOrWhiteSpace(catInfo.wszCatalogFile))
                            {
                                continue;
                            }

                            var status = VerifyCatalogMember(
                                catInfo.wszCatalogFile,
                                memberTag,
                                filePath,
                                rawHandle,
                                hashPtr,
                                hashSize,
                                hCatInfo,
                                hCatAdmin);

                            var signer = TryExtractEmbeddedSignerSubject(catInfo.wszCatalogFile);
                            return (true, status == 0, signer, status);
                        }
                        finally
                        {
                            _ = CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                        }
                    }
                    finally
                    {
                        Marshal.FreeCoTaskMem(hashPtr);
                    }
                }
                finally
                {
                    if (addRefSuccess)
                    {
                        safeHandle.DangerousRelease();
                    }
                }
            }
            finally
            {
                _ = CryptCATAdminReleaseContext(hCatAdmin, 0);
            }
        }

        return null;
    }

    [SupportedOSPlatform("windows")]
    private static int VerifyCatalogMember(
        string catalogFilePath,
        string memberTag,
        string memberFilePath,
        IntPtr memberFileHandle,
        IntPtr hashPtr,
        uint hashSize,
        IntPtr hCatInfo,
        IntPtr hCatAdmin)
    {
        var catalogPtr = Marshal.StringToCoTaskMemUni(catalogFilePath);
        var tagPtr = Marshal.StringToCoTaskMemUni(memberTag);
        var memberPathPtr = Marshal.StringToCoTaskMemUni(memberFilePath);
        var catalogInfoPtr = IntPtr.Zero;

        try
        {
            var catData = new WINTRUST_CATALOG_INFO
            {
                cbStruct = checked((uint)Marshal.SizeOf<WINTRUST_CATALOG_INFO>()),
                dwCatalogVersion = 0,
                pcwszCatalogFilePath = catalogPtr,
                pcwszMemberTag = tagPtr,
                pcwszMemberFilePath = memberPathPtr,
                hMemberFile = memberFileHandle,
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = hashSize,
                pcCatalogContext = hCatInfo,
                hCatAdmin = hCatAdmin
            };

            catalogInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf<WINTRUST_CATALOG_INFO>());
            Marshal.StructureToPtr(catData, catalogInfoPtr, fDeleteOld: false);

            var trustData = new WINTRUST_DATA
            {
                cbStruct = checked((uint)Marshal.SizeOf<WINTRUST_DATA>()),
                pPolicyCallbackData = IntPtr.Zero,
                pSIPClientData = IntPtr.Zero,
                dwUIChoice = WtdUiNone,
                fdwRevocationChecks = WtdRevokeNone,
                dwUnionChoice = WtdChoiceCatalog,
                pInfoStruct = catalogInfoPtr,
                dwStateAction = WtdStateActionVerify,
                hWVTStateData = IntPtr.Zero,
                pwszURLReference = IntPtr.Zero,
                dwProvFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
                dwUIContext = 0,
                pSignatureSettings = IntPtr.Zero
            };

            var action = WinTrustActionGenericVerifyV2;
            var status = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            trustData.dwStateAction = WtdStateActionClose;
            _ = WinVerifyTrust(IntPtr.Zero, ref action, ref trustData);

            return status;
        }
        finally
        {
            if (catalogInfoPtr != IntPtr.Zero)
            {
                Marshal.DestroyStructure<WINTRUST_CATALOG_INFO>(catalogInfoPtr);
                Marshal.FreeCoTaskMem(catalogInfoPtr);
            }

            if (memberPathPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(memberPathPtr);
            }

            if (tagPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(tagPtr);
            }

            if (catalogPtr != IntPtr.Zero)
            {
                Marshal.FreeCoTaskMem(catalogPtr);
            }
        }
    }

    [SupportedOSPlatform("windows")]
    private static string? TryExtractEmbeddedSignerSubject(string filePath)
    {
        var ok = CryptQueryObject(
            CertQueryObjectFile,
            filePath,
            CertQueryContentFlagPkcs7SignedEmbed,
            CertQueryFormatFlagBinary,
            0,
            out _,
            out _,
            out _,
            out var hStore,
            out var hMsg,
            IntPtr.Zero);

        if (!ok || hStore == IntPtr.Zero)
        {
            if (hMsg != IntPtr.Zero)
            {
                _ = CryptMsgClose(hMsg);
            }

            return null;
        }

        try
        {
            var certContext = CertEnumCertificatesInStore(hStore, IntPtr.Zero);
            if (certContext == IntPtr.Zero)
            {
                return null;
            }

            try
            {
                var charCount = CertGetNameStringW(certContext, CertNameSimpleDisplayType, 0, IntPtr.Zero, IntPtr.Zero, 0);
                if (charCount <= 1)
                {
                    return null;
                }

                var buffer = Marshal.AllocCoTaskMem(checked((int)(charCount * 2)));
                try
                {
                    var written = CertGetNameStringW(certContext, CertNameSimpleDisplayType, 0, IntPtr.Zero, buffer, charCount);
                    if (written <= 1)
                    {
                        return null;
                    }

                    return Marshal.PtrToStringUni(buffer);
                }
                finally
                {
                    Marshal.FreeCoTaskMem(buffer);
                }
            }
            finally
            {
                _ = CertFreeCertificateContext(certContext);
            }
        }
        finally
        {
            _ = CertCloseStore(hStore, 0);
            if (hMsg != IntPtr.Zero)
            {
                _ = CryptMsgClose(hMsg);
            }
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, SetLastError = true)]
    private static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WINTRUST_DATA pWVTData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        string? pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        IntPtr hFile,
        ref uint pcbHash,
        IntPtr pbHash,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        IntPtr pbHash,
        uint cbHash,
        uint dwFlags,
        ref IntPtr phPrevCatInfo);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CATALOG_INFO psCatInfo,
        uint dwFlags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(
        IntPtr hCatAdmin,
        IntPtr hCatInfo,
        uint dwFlags);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptQueryObject(
        uint dwObjectType,
        string pvObject,
        uint dwExpectedContentTypeFlags,
        uint dwExpectedFormatTypeFlags,
        uint dwFlags,
        out uint pdwMsgAndCertEncodingType,
        out uint pdwContentType,
        out uint pdwFormatType,
        out IntPtr phCertStore,
        out IntPtr phMsg,
        IntPtr ppvContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    private static extern IntPtr CertEnumCertificatesInStore(IntPtr hCertStore, IntPtr pPrevCertContext);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint CertGetNameStringW(
        IntPtr pCertContext,
        uint dwType,
        uint dwFlags,
        IntPtr pvTypePara,
        IntPtr pszNameString,
        uint cchNameString);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertFreeCertificateContext(IntPtr pCertContext);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CertCloseStore(IntPtr hCertStore, uint dwFlags);

    [DllImport("crypt32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptMsgClose(IntPtr hCryptMsg);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfoStruct;
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CATALOG_INFO
    {
        public uint cbStruct;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }
}
