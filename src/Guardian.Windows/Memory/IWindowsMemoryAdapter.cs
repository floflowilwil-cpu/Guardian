using Guardian.Contracts.Memory;

namespace Guardian.Windows.Memory;

/// <summary>
/// Contrat d'adaptateur d'inspection défensive des métadonnées mémoire Windows, sans lecture de secrets.
/// </summary>
public interface IWindowsMemoryAdapter : IMemoryAnalyzer
{
}
