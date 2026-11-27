using System.Reflection;
using Guardian.Contracts.Common;
using Guardian.Contracts.Data;
using Guardian.Contracts.Network;
using Guardian.Contracts.Updates;

namespace Guardian.UnitTests.Contracts;

public class NetworkDataUpdateContractsTests
{
    private static readonly Type[] OwnedInterfaces =
    [
        typeof(INetworkMonitor),
        typeof(IThreatRepository),
        typeof(IEventRepository),
        typeof(IUpdateService)
    ];

    [Fact]
    public void OwnedInterfaces_AllAsyncMethods_ShouldAcceptCancellationToken()
    {
        foreach (var contract in OwnedInterfaces)
        {
            foreach (var method in contract.GetMethods().Where(m => !m.IsSpecialName))
            {
                Assert.True(
                    typeof(Task).IsAssignableFrom(method.ReturnType),
                    $"{contract.Name}.{method.Name} doit être asynchrone.");

                Assert.Contains(
                    method.GetParameters(),
                    p => p.ParameterType == typeof(CancellationToken));
            }
        }
    }

    [Fact]
    public void OwnedInterfaces_CancellationToken_ShouldBeLastOptionalParameter()
    {
        foreach (var contract in OwnedInterfaces)
        {
            foreach (var method in contract.GetMethods().Where(m => !m.IsSpecialName))
            {
                var last = method.GetParameters()[^1];
                Assert.Equal(typeof(CancellationToken), last.ParameterType);
                Assert.True(last.HasDefaultValue, $"{contract.Name}.{method.Name}: le jeton d'annulation doit être optionnel.");
            }
        }
    }

    [Fact]
    public void OwnedContractTypes_ShouldNotExposeForbiddenPrivacyMembers()
    {
        string[] forbidden = ["Password", "Secret", "PrivateKey", "Keystroke", "Token"];
        var namespaces = new[]
        {
            "Guardian.Contracts.Network",
            "Guardian.Contracts.Data",
            "Guardian.Contracts.Updates"
        };

        var types = typeof(INetworkMonitor).Assembly
            .GetExportedTypes()
            .Where(t => namespaces.Contains(t.Namespace));

        foreach (var type in types)
        {
            foreach (var member in type.GetProperties().Select(p => p.Name))
            {
                foreach (var word in forbidden)
                {
                    Assert.DoesNotContain(word, member, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    [Fact]
    public void TemporaryBlockRequest_ShouldRequirePolicyDecisionAndDuration()
    {
        var parameters = typeof(TemporaryBlockRequest)
            .GetConstructors()
            .Single()
            .GetParameters()
            .Select(p => p.Name)
            .ToArray();

        Assert.Contains("PolicyDecisionId", parameters);
        Assert.Contains("Duration", parameters);
    }

    [Fact]
    public void FirewallContract_ShouldNotExposeAnyDisableOperation()
    {
        var names = typeof(INetworkMonitor).GetMethods().Select(m => m.Name).ToArray();

        foreach (var name in names)
        {
            Assert.DoesNotContain("Disable", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("TurnOff", name, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void UpdateRejectionReason_ShouldCoverTrustChainFailures()
    {
        var names = Enum.GetNames<UpdateRejectionReason>();

        Assert.Contains(nameof(UpdateRejectionReason.InvalidSignature), names);
        Assert.Contains(nameof(UpdateRejectionReason.HashMismatch), names);
        Assert.Contains(nameof(UpdateRejectionReason.DowngradeNotAllowed), names);
        Assert.Contains(nameof(UpdateRejectionReason.UntrustedSource), names);
    }

    [Fact]
    public void NetworkEventDto_ShouldCarryDecisionAndAppliedRule()
    {
        var evt = new NetworkEventDto(
            Guid.NewGuid(),
            DateTimeOffset.UtcNow,
            NetworkEventKind.ConnectionObserved,
            EventSeverity.Info,
            null,
            null,
            null,
            null,
            NetworkDecision.None,
            null,
            "test",
            new Dictionary<string, string>());

        Assert.Equal(NetworkDecision.None, evt.Decision);
        Assert.Null(evt.AppliedRuleId);
    }

    [Fact]
    public void PagedResult_ShouldKeepItemsAndTotal()
    {
        var page = new PagedResult<string>(["a", "b"], 10);

        Assert.Equal(2, page.Items.Count);
        Assert.Equal(10, page.TotalCount);
    }

    [Fact]
    public void ThreatQuery_ShouldHaveSafePaginationDefaults()
    {
        var query = new ThreatQuery();

        Assert.Equal(0, query.Skip);
        Assert.InRange(query.Take, 1, 1000);
    }
}
