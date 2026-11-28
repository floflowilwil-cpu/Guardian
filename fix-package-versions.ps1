# Retire les attributs Version="..." des <PackageReference> dans src\ et tests\
# (les versions sont gérées centralement dans Directory.Packages.props).
# Affiche chaque version retirée pour que tu puisses la comparer à Directory.Packages.props.
$ErrorActionPreference = 'Stop'

$pattern = '(<PackageReference\s+Include="[^"]+")\s+Version="([^"]+)"'
$roots = @((Join-Path $PSScriptRoot 'src'), (Join-Path $PSScriptRoot 'tests'))
$changedFiles = 0

Get-ChildItem -Path $roots -Recurse -Filter '*.csproj' | ForEach-Object {
    $content = [System.IO.File]::ReadAllText($_.FullName)
    $found = [regex]::Matches($content, $pattern)

    if ($found.Count -gt 0) {
        foreach ($m in $found) {
            $name = [regex]::Match($m.Groups[1].Value, 'Include="([^"]+)"').Groups[1].Value
            Write-Host ("{0} : {1} {2}" -f $_.Name, $name, $m.Groups[2].Value)
        }

        $updated = [regex]::Replace($content, $pattern, '$1')
        [System.IO.File]::WriteAllText($_.FullName, $updated, (New-Object System.Text.UTF8Encoding($true)))
        $changedFiles++
    }
}

Write-Host ""
Write-Host ("Fichiers modifiés : {0}" -f $changedFiles)
