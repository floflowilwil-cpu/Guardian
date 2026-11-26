using System.Reflection;
using Guardian.Contracts.Common;
using Guardian.Contracts.Health;
using Guardian.Contracts.Ipc;
using Guardian.Contracts.Memory;
using Guardian.Contracts.System;

namespace Guardian.UnitTests.Contracts;

public class SystemServiceContractsTests
{
    private static readonly string[] ForbiddenPrivacyTerms =
    [
        "Password",
        "Secret",
        "PrivateKey",
        "Keystroke",
        "Token"
    ];

    [Fact]
    public void GuardianHealthStatus_ShouldContainExactFiveSpecificationStates()
    {
        var names = Enum.GetNames<GuardianHealthStatus>();

        Assert.Equal(5, names.Length);
        Assert.Contains("Unknown", names);
        Assert.Contains("Healthy", names);
        Assert.Contains("Degraded", names);
        Assert.Contains("Stopped", names);
        Assert.Contains("OutOfDate", names);
    }

    [Fact]
    public void ContractsAssembly_PublicTypesShouldNotExposeForbiddenPrivacyMembers()
    {
        var assembly = typeof(IGuardianHealthService).Assembly;
        var publicTypes = assembly.GetExportedTypes();

        foreach (var type in publicTypes)
        {
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                foreach (var forbidden in ForbiddenPrivacyTerms)
                {
                    Assert.DoesNotContain(forbidden, property.Name, StringComparison.OrdinalIgnoreCase);
                }
            }

            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static))
            {
                foreach (var forbidden in ForbiddenPrivacyTerms)
                {
                    Assert.DoesNotContain(forbidden, field.Name, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    [Fact]
    public void IpcProtocolConstants_AndCommands_ShouldEnforceBoundedAndTypedRules()
    {
        Assert.False(string.IsNullOrWhiteSpace(IpcProtocolConstants.ProtocolVersion));
        Assert.False(string.IsNullOrWhiteSpace(IpcProtocolConstants.DefaultPipeName));
        Assert.InRange(IpcProtocolConstants.DefaultMaxMessageBytes, 1024, 1024 * 1024);
        Assert.True(IpcProtocolConstants.DefaultTimeout > TimeSpan.Zero);

        var commandNames = Enum.GetNames<IpcCommandType>();
        Assert.Contains(nameof(IpcCommandType.Unknown), commandNames);
        Assert.Contains(nameof(IpcCommandType.Ping), commandNames);
        Assert.Contains(nameof(IpcCommandType.GetHealth), commandNames);

        foreach (var name in commandNames)
        {
            Assert.DoesNotContain("Shell", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Exec", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Cmd", name, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("Arbitrary", name, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void MandatoryServiceAndSystemInterfaces_ShouldBePresentInContractsAssembly()
    {
        var assembly = typeof(IGuardianHealthService).Assembly;
        var expectedInterfaces = new[]
        {
            typeof(IGuardianHealthService),
            typeof(ISystemMonitor),
            typeof(IBehaviorMonitor),
            typeof(IMemoryAnalyzer),
            typeof(IIpcRequestDispatcher)
        };

        foreach (var expected in expectedInterfaces)
        {
            Assert.True(expected.IsInterface, $"{expected.Name} must be an interface.");
            Assert.Same(assembly, expected.Assembly);
        }
    }
}
