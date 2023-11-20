# script for executing measurements

$count = 20

# setup arguments
$javaCommand = "java"
$jarPath = "build/libs/JCProfilerNext-1.0-SNAPSHOT.jar"
$workDir = "jcfrost"
$jckit = "./jcfrost/libs-sdks/jc305u3_kit"
$cla = "00"
$ins = "02"
$p1 = "40"
$p2 = "00"
$entryPoint = "jcfrost.JCFROST"
$executable = "jcfrost.FrostSession#commit"
$repeatCount = 10 # set number of rounds for profiling
$threshold = 1
$parties = 2
$stage = 1
$startFrom = "profiling"

# create directory for measurements
$rootDirectoryName = Join-Path -Path $workDir -ChildPath "measurements"
New-Item -ItemType Directory -Path $rootDirectoryName | Out-Null

for ($i = 1; $i -le $count; $i++) {
    # Generate random hex strings
    $randomBytes = New-Object byte[] 32
    $randomNumberGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $randomNumberGenerator.GetBytes($randomBytes)
    $secret = "80E265031D995699402045CAF36630E718CABDB9F3443F8FFC79F0C3943B8199"

    $randomBytes = New-Object byte[] 64
    $randomNumberGenerator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $randomNumberGenerator.GetBytes($randomBytes)
    $nonce = [BitConverter]::ToString($randomBytes) -replace '-'

    # Print random hex strings
    Write-Host "Running measurement $i for:"
    Write-Host "Secret: $secret"
    Write-Host "Nonce: $nonce"

# Construct the argument string
$arguments = @"
-jar "$jarPath" --work-dir "$workDir" --jckit "$jckit" --cla "$cla" --ins "$ins" --p1 "$p1" --p2 "$p2" --data-regex "$nonce" --secret "$secret" --entry-point "$entryPoint" --executable "$executable" --repeat-count $repeatCount --threshold $threshold --parties $parties --stage $stage --start-from "$startFrom"
"@

    # Run the Java command
    Start-Process -FilePath $javaCommand -ArgumentList $arguments -Wait

    # Move into new directory
    $directoryName = Join-Path -Path $rootDirectoryName -ChildPath "Round$i"
    New-Item -ItemType Directory -Path $directoryName | Out-Null
    Move-Item -Path "$workDir/measurements.csv" -Destination "$directoryName/measurements.csv" -Force
    Move-Item -Path "$workDir/measurements.html" -Destination "$directoryName/measurements.html" -Force
}

