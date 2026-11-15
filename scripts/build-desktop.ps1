param(
    [string] $OutputDirectory
)

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $repo 'dist' }
$stage = Join-Path ([IO.Path]::GetTempPath()) ('FoxyProxy-' + [guid]::NewGuid().ToString('N'))
$package = Join-Path $stage 'FoxyProxy'
$archive = Join-Path $OutputDirectory 'FoxyProxy-Windows.zip'
$singVersion = '1.14.4'
$targets = @(
    @{ Rid = 'win-x64';   Folder = 'Windows-x64';   GoArch = 'amd64'; Hash = '99185D75D314A07DBBA4A130C8AD986CBEB629A07927975636B341CA61F991DF' }
    @{ Rid = 'win-x86';   Folder = 'Windows-x86';   GoArch = '386';   Hash = '7994C40C5C1316777BDD29216A5DD7F134F894FAD0AFAA1EFE7B872E60ED1DD9' }
    @{ Rid = 'win-arm64'; Folder = 'Windows-ARM64'; GoArch = 'arm64'; Hash = '8CD0A4D0CD8CD480BE5731AC31F17038969A42D12ADD9FEB6E031FD43D85BBAE' }
)
$previousArch = $env:GOARCH
$previousOS = $env:GOOS
$nativeArch = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
$installer = Join-Path $package 'MicrosoftEdgeWebview2Setup.exe'

New-Item -ItemType Directory -Path $package, $OutputDirectory -Force | Out-Null
Push-Location $repo
try {
    curl.exe --fail --location --retry 4 --retry-all-errors --silent --show-error --output $installer 'https://go.microsoft.com/fwlink/p/?LinkId=2124703'
    if ($LASTEXITCODE -ne 0) { throw 'WebView2 installer download failed' }
    $signature = Get-AuthenticodeSignature -LiteralPath $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch '^CN=Microsoft Corporation,') {
        throw 'WebView2 installer signature verification failed'
    }

    $env:GOOS = 'windows'
    $config = (Get-Content -Raw -LiteralPath 'cmd/proxy-demo/tun.json').Replace('%d', '1080')
    foreach ($target in $targets) {
        $app = Join-Path $package $target.Folder
        dotnet publish 'desktop/FoxyProxy.csproj' -c Release -r $target.Rid --self-contained true `
            -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true -p:DebugType=None -o $app
        if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed for $($target.Rid)" }

        $worker = Join-Path $app 'foxy-worker.exe'
        $env:GOARCH = $target.GoArch
        go build -trimpath -o $worker ./cmd/proxy-demo
        if ($LASTEXITCODE -ne 0) { throw "go build failed for $($target.GoArch)" }

        $singName = "sing-box-$singVersion-windows-$($target.GoArch)"
        $singZip = Join-Path $stage "$singName.zip"
        $singUrl = "https://github.com/SagerNet/sing-box/releases/download/v$singVersion/$singName.zip"
        curl.exe --fail --location --retry 4 --retry-all-errors --silent --show-error --output $singZip $singUrl
        if ($LASTEXITCODE -ne 0) { throw "sing-box download failed for $($target.GoArch)" }
        if ((Get-FileHash -LiteralPath $singZip -Algorithm SHA256).Hash -ne $target.Hash) {
            throw "sing-box SHA-256 verification failed for $($target.GoArch)"
        }
        Expand-Archive -LiteralPath $singZip -DestinationPath $stage
        Move-Item -LiteralPath (Join-Path $stage $singName) -Destination (Join-Path $app 'tun')

        if ($target.Rid -eq "win-$nativeArch" -or ($nativeArch -eq 'X64' -and $target.GoArch -eq '386')) {
            $workerPattern = '(?i)^' + [regex]::Escape($worker) + '$'
            $workerPath = ConvertTo-Json -InputObject $workerPattern -Compress
            $config.Replace('%s', $workerPath) | & (Join-Path $app 'tun/sing-box.exe') check -c stdin
            if ($LASTEXITCODE -ne 0) { throw "sing-box configuration check failed for $($target.GoArch)" }
        }
    }

    Copy-Item -LiteralPath 'desktop/README.ru.md' -Destination $package
    Copy-Item -LiteralPath 'desktop/LICENSE.FoxyVPN' -Destination $package
    Copy-Item -LiteralPath 'LICENSE' -Destination $package
    Compress-Archive -LiteralPath $package -DestinationPath $archive -CompressionLevel Optimal -Force
    Write-Output $archive
}
finally {
    Pop-Location
    $env:GOARCH = $previousArch
    $env:GOOS = $previousOS
    $resolvedStage = (Resolve-Path -LiteralPath $stage).Path
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if ($resolvedStage.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedStage) -match '^FoxyProxy-[0-9a-f]{32}$') {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force
    }
}
