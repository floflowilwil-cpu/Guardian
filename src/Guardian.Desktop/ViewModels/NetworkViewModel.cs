using System.Collections.ObjectModel;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;

namespace Guardian.Desktop.ViewModels;

public sealed class NetworkViewModel : ObservableObject, IPage
{
    private int _active;
    private int _suspicious;
    private bool _hasData;

    public ObservableCollection<NetworkDestination> Destinations { get; } = new();

    public int Active { get => _active; private set => Set(ref _active, value); }

    public int Suspicious { get => _suspicious; private set => Set(ref _suspicious, value); }

    public bool HasData { get => _hasData; private set => Set(ref _hasData, value); }

    public void Apply(GuardianSnapshot s)
    {
        Active = s.ActiveConnections;
        Suspicious = s.SuspiciousConnections;
        HasData = s.State != ProtectionState.Unknown;
        Destinations.Clear();
        foreach (var d in s.Destinations)
        {
            Destinations.Add(d);
        }
    }
}
