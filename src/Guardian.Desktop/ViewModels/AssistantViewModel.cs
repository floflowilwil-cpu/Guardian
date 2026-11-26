using System.Collections.ObjectModel;
using System.Windows.Input;
using Guardian.Desktop.Infrastructure;
using Guardian.Desktop.Models;
using Guardian.Desktop.Services;

namespace Guardian.Desktop.ViewModels;

public sealed class AssistantViewModel : ObservableObject, IPage
{
    private readonly IGuardianClient _client;
    private string _input = string.Empty;
    private bool _busy;

    public AssistantViewModel(IGuardianClient client)
    {
        _client = client;
        Messages.Add(new ChatMessage("Bonjour ! Je suis Guardian IA. Comment puis-je vous aider ?", false));
        SendCommand = new RelayCommand(async () => await SendAsync(Input), () => !_busy && !string.IsNullOrWhiteSpace(Input));
        SuggestCommand = new RelayCommand(async p =>
        {
            if (p is string text)
            {
                await SendAsync(text);
            }
        });
    }

    public ObservableCollection<ChatMessage> Messages { get; } = new();

    public IReadOnlyList<string> Suggestions { get; } =
    [
        "Pourquoi ce fichier est-il bloqué ?",
        "Voir les menaces liées",
        "Analyser un fichier",
    ];

    public ICommand SendCommand { get; }

    public ICommand SuggestCommand { get; }

    public string Input { get => _input; set => Set(ref _input, value); }

    public void Apply(GuardianSnapshot snapshot)
    {
    }

    private async Task SendAsync(string text)
    {
        if (_busy || string.IsNullOrWhiteSpace(text))
        {
            return;
        }

        _busy = true;
        Input = string.Empty;
        Messages.Add(new ChatMessage(text, true));
        try
        {
            var answer = await _client.AskAssistantAsync(text);
            Messages.Add(new ChatMessage(
                answer ?? "L'assistant local n'est pas joignable : le service Guardian ne répond pas.",
                false));
        }
        finally
        {
            _busy = false;
        }
    }
}
