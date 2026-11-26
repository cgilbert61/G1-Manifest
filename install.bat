@echo off
setlocal
echo === G1-Manifest One-Click Docker Installer (G1163RT Security Labs) ===
docker compose up -d --build
if errorlevel 1 (
    echo ERROR: docker compose failed. Ensure Docker Desktop is running.
    exit /b 1
)
echo Waiting for G1-Manifest health endpoint on http://127.0.0.1:8088/health ...
powershell -NoProfile -Command "$ok=$false; for($i=0;$i -lt 30;$i++){ try { $r=Invoke-WebRequest -Uri 'http://127.0.0.1:8088/health' -UseBasicParsing -TimeoutSec 2; if($r.StatusCode -eq 200){ Write-Host 'G1-Manifest is healthy!' -ForegroundColor Green; $ok=$true; break } } catch {}; Start-Sleep -Seconds 1 }; if(-not $ok){ exit 1 }"
if errorlevel 1 (
    echo ERROR: G1-Manifest did not become healthy within 30 seconds.
    exit /b 1
)
echo Open http://127.0.0.1:8088/ in your browser.
endlocal
