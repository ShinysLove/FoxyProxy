using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using Microsoft.Web.WebView2.Core;

namespace FoxyProxy;

public partial class MozillaSignIn : Window
{
    private const string LoginUrl = "https://accounts.firefox.com/?context=fx_desktop_v3&service=sync&action=email";
    private bool closed;
    private bool accepted;
    public string? Session { get; private set; }

    public MozillaSignIn()
    {
        InitializeComponent();
        Loaded += InitializeBrowser;
        Closed += (_, _) =>
        {
            closed = true;
            Browser.Dispose();
        };
    }

    private async void InitializeBrowser(object sender, RoutedEventArgs e)
    {
        Loaded -= InitializeBrowser;
        try
        {
            var profileDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "FoxyProxy", "WebView");
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: profileDir);
            if (closed) return;
            var options = environment.CreateCoreWebView2ControllerOptions();
            options.IsInPrivateModeEnabled = true;
            await Browser.EnsureCoreWebView2Async(environment, options);
            if (closed) return;
            var web = Browser.CoreWebView2;
            web.Settings.AreHostObjectsAllowed = false;
            web.Settings.AreDevToolsEnabled = false;
            web.Settings.IsGeneralAutofillEnabled = false;
            web.Settings.IsPasswordAutosaveEnabled = false;
            web.Settings.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:159.0) Gecko/20100101 Firefox/159.0";
            web.NavigationStarting += (_, args) => args.Cancel = !IsMozillaOrigin(args.Uri);
            web.NewWindowRequested += (_, args) => args.Handled = true;
            web.PermissionRequested += (_, args) => args.State = CoreWebView2PermissionState.Deny;
            web.DownloadStarting += (_, args) => args.Cancel = true;
            web.NavigationCompleted += (_, args) =>
            {
                if (!args.IsSuccess && args.WebErrorStatus != CoreWebView2WebErrorStatus.OperationCanceled)
                    BrowserStatus.Text = "Не удалось открыть страницу Mozilla. Проверьте интернет и откройте вход снова.";
            };
            web.WebMessageReceived += OnBrowserMessage;
            using var resource = typeof(MozillaSignIn).Assembly.GetManifestResourceStream("FoxyProxy.MozillaChannel.js")
                ?? throw new InvalidOperationException("Missing MozillaChannel.js");
            using var reader = new StreamReader(resource);
            await web.AddScriptToExecuteOnDocumentCreatedAsync(await reader.ReadToEndAsync());
            if (!closed) web.Navigate(LoginUrl);
        }
        catch (WebView2RuntimeNotFoundException)
        {
            if (!closed) BrowserStatus.Text = "Для входа запустите MicrosoftEdgeWebview2Setup.exe из архива, затем откройте вход снова.";
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.Runtime.InteropServices.COMException or IOException
                                   or UnauthorizedAccessException or ArgumentException)
        {
            if (!closed) BrowserStatus.Text = "Не удалось запустить окно Mozilla. Откройте вход снова.";
        }
    }

    private void OnBrowserMessage(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        var web = Browser.CoreWebView2;
        if (closed || accepted || web is null || !IsMozillaOrigin(e.Source) || !IsMozillaOrigin(web.Source))
            return;
        var raw = e.WebMessageAsJson;
        if (raw.Length > 32768)
            return;
        try
        {
            using var json = JsonDocument.Parse(raw);
            var root = json.RootElement;
            var id = StringProperty(root, "id");
            if (id != "account_updates" && id.Length != 0)
                return;
            if (!root.TryGetProperty("message", out var message) || message.ValueKind != JsonValueKind.Object)
                return;
            var command = StringProperty(message, "command");
            var messageId = StringProperty(message, "messageId");
            switch (command)
            {
                case "fxaccounts:fxa_status":
                    Reply(web, messageId, command, new { capabilities = new { }, signedInUser = (object?)null });
                    break;
                case "fxaccounts:can_link_account":
                    Reply(web, messageId, command, new { ok = true });
                    break;
                case "fxaccounts:login":
                case "fxaccounts:verified":
                case "fxaccounts:oauth_login":
                    if (!message.TryGetProperty("data", out var data) || data.ValueKind != JsonValueKind.Object)
                        return;
                    var token = StringProperty(data, "sessionToken").Trim();
                    if (token.Length == 0) token = StringProperty(data, "token").Trim();
                    if (!Regex.IsMatch(token, "\\A[0-9a-fA-F]{64}\\z", RegexOptions.CultureInvariant))
                        return;
                    Reply(web, messageId, command, new { ok = true });
                    accepted = true;
                    Session = token;
                    // Let Mozilla show the verification page while the worker polls.
                    SessionReceived?.Invoke(this, EventArgs.Empty);
                    break;
            }
        }
        catch (JsonException) { }
    }

    public event EventHandler? SessionReceived;

    public void ShowProgress(string? message)
    {
        if (!closed && !string.IsNullOrEmpty(message))
            BrowserStatus.Text = message;
    }

    private static void Reply(CoreWebView2 web, string messageId, string command, object data)
    {
        web.PostWebMessageAsJson(JsonSerializer.Serialize(new
        {
            id = "account_updates",
            message = new { messageId, command, data }
        }));
    }

    private static string StringProperty(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var property) &&
        property.ValueKind == JsonValueKind.String ? property.GetString() ?? "" : "";

    private static bool IsMozillaOrigin(string? source) =>
        Uri.TryCreate(source, UriKind.Absolute, out var uri) &&
        uri.Scheme == Uri.UriSchemeHttps && uri.IsDefaultPort && uri.Host == "accounts.firefox.com";
}
