using System.ComponentModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Automation;
using System.Windows.Media;

namespace FoxyProxy;

public partial class MainWindow : Window
{
    private enum ConnectionState { CheckingSession, Off, SigningIn, LoadingServers, Starting, Connected, Stopping }
    private sealed record WorkerEvent(string Type, string? Message, string? Address, ulong SentBytes,
        ulong ReceivedBytes, string? Server, ServerOption[]? Servers);
    private sealed record ServerOption(string ID, string Label, long? LatencyMs)
    {
        public string Display => ID.Length == 0 ? Label : $"{Label} · {LatencyLabel}";

        private string LatencyLabel => LatencyMs is { } ms ? $"{ms} мс" : "нет ответа";
    }

    private static readonly CultureInfo Russian = CultureInfo.GetCultureInfo("ru-RU");
    private static readonly Brush Active = new SolidColorBrush(Color.FromRgb(27, 110, 47));
    private static readonly Brush Busy = new SolidColorBrush(Color.FromRgb(138, 90, 0));
    private static readonly Brush Idle = new SolidColorBrush(Color.FromRgb(160, 58, 0));
    private static readonly string CachePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "FoxyProxy", "session.dat");
    private ConnectionState state;
    private Process? worker;
    private Task? workerLifetime;
    private MozillaSignIn? signIn;
    private bool signedIn;
    private bool closing;
    private bool canClose;

    public MainWindow()
    {
        InitializeComponent();
        ShowServers([]);
        ShowTraffic(0, 0);
        ModeChanged(this, new RoutedEventArgs());
        SetState(ConnectionState.Off, "Войдите в аккаунт Mozilla.");
        if (File.Exists(CachePath))
            Loaded += RestoreSession;
    }

    private void RestoreSession(object sender, RoutedEventArgs e)
    {
        Loaded -= RestoreSession;
        StartWorker("restore");
    }

    private bool WholePc => WholePcMode.IsChecked == true;

    private void RefreshServers(object sender, RoutedEventArgs e)
    {
        if (state == ConnectionState.Off)
            StartWorker("servers");
    }

    private void ShowServers(ServerOption[] servers)
    {
        var selected = ServerChoice.SelectedValue as string;
        ServerChoice.ItemsSource = new[] { new ServerOption("", "Автоматически", null) }
            .Concat(servers.OrderBy(server => server.LatencyMs ?? long.MaxValue)
                .ThenBy(server => server.Label, StringComparer.CurrentCultureIgnoreCase))
            .ToArray();
        ServerChoice.SelectedValue = selected ?? "";
        if (ServerChoice.SelectedIndex < 0)
            ServerChoice.SelectedIndex = 0;
    }

    private void ModeChanged(object sender, RoutedEventArgs e)
    {
        if (ModeDescription is not null)
            ModeDescription.Text = WholePc
                ? "TCP и DNS через виртуальный адаптер Windows."
                : "Для приложений с настройкой SOCKS5. Адрес 127.0.0.1:1080.";
    }

    private void AccountAction(object sender, RoutedEventArgs e)
    {
        if (state != ConnectionState.Off)
            return;
        if (!signedIn)
        {
            OpenSignIn();
            return;
        }
        try
        {
            File.Delete(CachePath);
            signedIn = false;
            SetState(ConnectionState.Off, "Сохранённая сессия удалена.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            StatusText.Text = "Не удалось удалить сохранённую сессию.";
        }
    }

    private void OpenSignIn()
    {
        var dialog = new MozillaSignIn { Owner = this };
        signIn = dialog;
        dialog.SessionReceived += (_, _) =>
        {
            if (dialog.Session is { } session)
            {
                if (!StartWorker("login", session))
                    dialog.Close();
            }
        };
        dialog.Closed += async (_, _) =>
        {
            signIn = null;
            if (state == ConnectionState.SigningIn && worker is not null)
                await StopAsync();
        };
        dialog.ShowDialog();
    }

    private async void ToggleConnection(object sender, RoutedEventArgs e)
    {
        switch (state)
        {
            case ConnectionState.Off when signedIn:
                StartWorker(WholePc ? "tun" : "socks");
                break;
            case ConnectionState.Connected:
            case ConnectionState.Starting:
                await StopAsync();
                break;
        }
    }

    private bool StartWorker(string mode, string? session = null)
    {
        var process = new Process
        {
            StartInfo = new ProcessStartInfo(Path.Combine(AppContext.BaseDirectory, "foxy-worker.exe"), "-desktop-worker")
            {
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardInputEncoding = new UTF8Encoding(false),
                StandardOutputEncoding = Encoding.UTF8
            }
        };
        try
        {
            process.Start();
        }
        catch (Win32Exception)
        {
            process.Dispose();
            const string message = "Не удалось запустить компонент прокси. Распакуйте весь архив.";
            if (mode == "servers")
                ServerStatus.Text = message;
            else
                StatusText.Text = message;
            return false;
        }
        worker = process;
        switch (mode)
        {
            case "login":
                SetState(ConnectionState.SigningIn, "Проверяем вход в Mozilla…");
                break;
            case "restore":
                SetState(ConnectionState.CheckingSession, "Читаем сохранённую сессию…");
                break;
            case "servers":
                SetState(ConnectionState.LoadingServers, StatusText.Text);
                ServerStatus.Text = "Измеряем задержку до серверов…";
                break;
            default:
                SetState(ConnectionState.Starting, "Запуск подключения…");
                break;
        }
        var server = mode is "tun" or "socks" ? ServerChoice.SelectedValue as string : null;
        workerLifetime = WatchWorkerAsync(process, mode,
            JsonSerializer.Serialize(new { Mode = mode, Session = session, Server = server }));
        return true;
    }

    private async Task WatchWorkerAsync(Process process, string mode, string? request)
    {
        var drain = process.StandardError.BaseStream.CopyToAsync(Stream.Null);
        string? error = null;
        var authenticated = false;
        var serversLoaded = false;
        try
        {
            await process.StandardInput.WriteLineAsync(request);
            request = null;
            while (await process.StandardOutput.ReadLineAsync() is { } line)
            {
                var message = JsonSerializer.Deserialize<WorkerEvent>(line);
                if (state == ConnectionState.Stopping && message?.Type != "traffic")
                    continue;
                switch (message?.Type)
                {
                    case "progress":
                        StatusText.Text = message.Message ?? "";
                        signIn?.ShowProgress(message.Message);
                        break;
                    case "authenticated":
                        authenticated = signedIn = true;
                        break;
                    case "reauthenticate":
                        signedIn = false;
                        break;
                    case "connected":
                        ShowTraffic(0, 0);
                        TrafficCard.Visibility = Visibility.Visible;
                        ProxyAddress.Text = message.Address ?? "";
                        if (!string.IsNullOrEmpty(message.Server))
                            ServerStatus.Text = $"Подключено к {message.Server}";
                        SetState(ConnectionState.Connected, WholePc
                            ? "TCP и DNS Windows идут через прокси."
                            : "Укажите этот адрес в настройках SOCKS5.");
                        break;
                    case "servers" when message.Servers is { } servers:
                        ShowServers(servers);
                        ServerStatus.Text = $"Серверов: {servers.Length}, ответили: {servers.Count(server => server.LatencyMs.HasValue)}.";
                        serversLoaded = true;
                        break;
                    case "traffic":
                        ShowTraffic(message.SentBytes, message.ReceivedBytes);
                        break;
                    case "error":
                        error = message.Message;
                        break;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or JsonException or InvalidOperationException)
        {
            error = "Связь с компонентом прокси прервалась.";
            CloseInput(process);
            await WaitForExitAsync(process);
        }
        finally
        {
            await process.WaitForExitAsync();
            await drain;
            var stopped = state == ConnectionState.Stopping;
            worker = null;
            process.Dispose();
            ProxyAddress.Clear();
            if (mode == "servers")
            {
                if (!serversLoaded)
                    ServerStatus.Text = error ?? "Проверка серверов завершилась. Обновите пинг ещё раз.";
                SetState(ConnectionState.Off, StatusText.Text);
            }
            else
            {
                if (ServerStatus.Text.StartsWith("Подключено к ", StringComparison.Ordinal))
                    ServerStatus.Text = "Обновите пинг, чтобы проверить задержку.";
                SetState(ConnectionState.Off, stopped ? (signedIn ? "Прокси выключен." : "Войдите в аккаунт Mozilla.")
                    : authenticated ? "Нажмите кнопку питания для подключения."
                    : mode == "restore" && error is null ? "Войдите в аккаунт Mozilla."
                    : error ?? "Компонент прокси завершился. Попробуйте снова.");
            }
            if (mode == "login")
                signIn?.Close();
        }
    }

    private void ShowTraffic(ulong sent, ulong received)
    {
        const decimal bytesPerGigabyte = 1_000_000_000m;
        TrafficTotal.Text = string.Format(Russian, "{0:0.000######} ГБ", ((decimal)sent + received) / bytesPerGigabyte);
        TrafficBreakdown.Text = string.Format(Russian, "Получено {0:0.000######} ГБ · Отправлено {1:0.000######} ГБ",
            received / bytesPerGigabyte, sent / bytesPerGigabyte);
    }

    private async Task StopAsync()
    {
        var process = worker;
        if (process is null)
            return;
        if (state != ConnectionState.Stopping)
        {
            SetState(ConnectionState.Stopping, "Отключение…");
            CloseInput(process);
            await WaitForExitAsync(process);
        }
        if (workerLifetime is not null)
            await workerLifetime;
    }

    private static void CloseInput(Process process)
    {
        try { process.StandardInput.Close(); }
        catch (Exception ex) when (ex is IOException or InvalidOperationException) { }
    }

    private static async Task WaitForExitAsync(Process process)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(9));
        try { await process.WaitForExitAsync(timeout.Token); }
        catch (OperationCanceledException)
        {
            try { process.Kill(); }
            catch (InvalidOperationException) { }
        }
        catch (InvalidOperationException) { }
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (canClose || worker is null)
        {
            base.OnClosing(e);
            return;
        }
        e.Cancel = true;
        if (closing)
            return;
        closing = true;
        await StopAsync();
        canClose = true;
        Close();
    }

    private void SetState(ConnectionState value, string message)
    {
        state = value;
        var off = value == ConnectionState.Off;
        var connected = value == ConnectionState.Connected;
        StatusTitle.Text = value switch
        {
            ConnectionState.Off => signedIn ? "Прокси выключен" : "Вход в Mozilla",
            ConnectionState.CheckingSession => "Проверка сессии",
            ConnectionState.SigningIn => "Вход в Mozilla",
            ConnectionState.LoadingServers => signedIn ? "Прокси выключен" : "Вход в Mozilla",
            ConnectionState.Connected => "Прокси включён",
            ConnectionState.Stopping => "Отключение",
            _ => "Подключение"
        };
        StatusText.Text = message;
        PowerButton.Foreground = connected ? Active : off ? Idle : Busy;
        PowerButton.Visibility = ModesCard.Visibility = signedIn ? Visibility.Visible : Visibility.Collapsed;
        PowerButton.IsEnabled = off || connected || value == ConnectionState.Starting;
        AutomationProperties.SetName(PowerButton, value switch
        {
            ConnectionState.Connected => "Выключить прокси",
            ConnectionState.Starting => "Отменить подключение",
            _ => "Включить прокси"
        });
        PowerButton.ToolTip = AutomationProperties.GetName(PowerButton);
        ModePanel.IsEnabled = AccountButton.IsEnabled = off;
        ServerChoice.IsEnabled = RefreshServersButton.IsEnabled = off;
        AccountButton.Content = signedIn ? "Выйти из аккаунта" : "Войти через Firefox";
        AccountHint.Text = signedIn ? "Сессия сохранена в профиле Windows." : "Откроется страница accounts.firefox.com.";
        ProxyAddress.Visibility = connected && !WholePc ? Visibility.Visible : Visibility.Collapsed;
    }
}
