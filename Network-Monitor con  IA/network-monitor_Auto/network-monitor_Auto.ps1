# ============================
# Monitor de conexiones salientes por proceso
# Listas blanca/negra, bloqueo automatico, geolocalizacion IP y log
# ============================

# === ARCHIVOS EN RAÍZ (NO EN CARPETAS) ===
$whitelistFile = "whitelist.txt"
$blacklistFile = "blacklist.txt"
$logFile = "log_conexiones.txt"

# === ARCHIVOS EN CARPETAS ===
$logDir = "logs"
$hashDir = "hashes"

$logCsvPath = "$logDir\log_conexiones.csv"
$logJsonPath = "$logDir\log_conexiones.json"
$unknownFile = "$logDir\desconocidas.txt"
$loggedEventsFile = "$logDir\logged_events.txt"
$edgeHashFile = "$hashDir\edge_hashes.json"
$edgePath = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

# === CREAR CARPETAS SI NO EXISTEN ===
@($logDir, $hashDir) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

# === CREAR ARCHIVOS EN RAÍZ SI NO EXISTEN ===
if (-not (Test-Path $whitelistFile)) { "" | Out-File $whitelistFile }
if (-not (Test-Path $blacklistFile)) {
    "IP                  | Proceso          | Organizacion     | Motivo                 | Efectos si se bloquea" | Out-File $blacklistFile
    "----------------|------------------|------------------|------------------------|-----------------------------------" | Out-File $blacklistFile -Append
}
if (-not (Test-Path $logFile)) {
    ""
    "==================== INICIO DEL MONITOREO ===================="
    "" | Out-File $logFile
}

# === CREAR ARCHIVOS EN CARPETAS SI NO EXISTEN ===
if (-not (Test-Path $unknownFile)) { "" | Out-File $unknownFile }
if (-not (Test-Path $loggedEventsFile)) { @() | Out-File $loggedEventsFile }
if (-not (Test-Path $edgeHashFile)) { @() | ConvertTo-Json | Out-File -Encoding UTF8 $edgeHashFile }

# === LISTAS GLOBALES ===
$global:whitelist = @()
$global:blacklistData = @()
$global:blacklist = @()
$global:unknownlist = @()
$global:loggedEvents = @()  # ✅ Inicializar vacío

# ============================ FUNCIONES ============================

function Cargar-Listas {
    $global:whitelist = Get-Content $whitelistFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
    
    $global:blacklistData = @()
    if (Test-Path $blacklistFile) {
        $lineas = Get-Content $blacklistFile | Where-Object { 
            $_ -match '\d+\.\d+\.\d+\.\d+' -and 
            $_ -notmatch '^-{10,}' -and 
            $_ -notmatch 'IP\s+\|'
        }
        
        foreach ($linea in $lineas) {
            $campos = $linea -split '\|' | ForEach-Object { $_.Trim() }
            if ($campos.Count -ge 2) {
                $ip = $campos[0] -replace '[^\d\.]', ''
                $proceso = $campos[1]
                $organizacion = if ($campos.Count -gt 2) { $campos[2] } else { "Desconocido" }
                $motivo = if ($campos.Count -gt 3) { $campos[3] } else { "Bloqueo automático" }
                $efectos = if ($campos.Count -gt 4) { $campos[4] } else { "Impacto desconocido" }
                
                if ($ip -match '\d+\.\d+\.\d+\.\d+') {
                    $global:blacklistData += [PSCustomObject]@{
                        IP = $ip
                        Proceso = $proceso
                        Organizacion = $organizacion
                        Motivo = $motivo
                        Efectos = $efectos
                    }
                }
            }
        }
    }
    $global:blacklist = $global:blacklistData.IP
    $global:unknownlist = Get-Content $unknownFile -ErrorAction SilentlyContinue | Where-Object { $_ -match '\d+\.\d+\.\d+\.\d+' }
}

function Obtener-GeolocalizacionIP($ip) {
    try {
        $resp = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip" -TimeoutSec 5
        return "$($resp.country), $($resp.city), Org: $($resp.org)"
    } catch {
        return "Ubicacion no disponible"
    }
}

function EsIPPuertaDeEnlace($ip) {
    $puertas = @("192.168.1.1", "192.168.0.1", "10.0.0.1", "10.0.1.1", "172.0.0.1", "172.0.1.1")
    return $puertas -contains $ip
}

function Obtener-ConexionesActivas {
    Get-NetTCPConnection | Where-Object {
        $_.RemoteAddress -ne '127.0.0.1' -and
        $_.RemoteAddress -ne '::1' -and
        $_.RemoteAddress -ne '0.0.0.0' -and
        $_.State -eq 'Established'
    } | Group-Object -Property OwningProcess
}

function Obtener-Hash($path) {
    if (Test-Path $path) {
        return (Get-FileHash -Path $path -Algorithm SHA256).Hash
    }
    return ""
}

function Registrar-HashEdgeSiNuevo {
    if (-not (Test-Path $edgePath)) { return $false }
    $hashActual = Obtener-Hash $edgePath
    if (-not $hashActual) { return $false }
    $historial = @()
    try {
        $contenido = Get-Content $edgeHashFile -Raw
        if ($contenido.Trim()) {
            $historial = $contenido | ConvertFrom-Json
            if ($historial -isnot [array]) { $historial = @($historial) }
        }
    } catch { $historial = @() }
    $existe = $historial | Where-Object { $_.Hash -eq $hashActual }
    if (-not $existe) {
        $nuevo = [PSCustomObject]@{
            Fecha = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Hash  = $hashActual
            Ruta  = $edgePath
        }
        $historial += $nuevo
        $historial | ConvertTo-Json -Depth 2 | Out-File -Encoding UTF8 $edgeHashFile
    }
    return $hashActual
}

function EsHashEdgeValido($hash) {
    if (-not $hash) { return $false }
    $historial = @()
    try {
        $contenido = Get-Content $edgeHashFile -Raw
        if ($contenido.Trim()) {
            $historial = $contenido | ConvertFrom-Json
            if ($historial -isnot [array]) { $historial = @($historial) }
        }
    } catch { return $false }
    return ($historial.Hash -contains $hash)
}

function EsPrimeraVez {
    $ahora = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $lineas = @()
    $lineas += ""
    $lineas += "==================== INICIO DEL MONITOREO ===================="
    $lineas += "$ahora -"
    $lineas += "Actua como un EDR o un XDR profesional."
    $lineas += "Analiza estas conexiones salientes, evalua IPs, rutas del ejecutable y anomalias de ruta e IP."
    $lineas += ""
    $lineas += "Actualiza o dame un listado de estas IPs:"
    $lineas += " Lista negra:"
    $lineas += "  Formato: Salida (formato TXT listo para pegar): MODO CONSOLA para solo copiar tipo pgsql o diff."
    $lineas += "IP                  | Proceso          | Organizacion     | Motivo                 | Efectos si se bloquea"
    $lineas += "----------------|------------------|------------------|------------------------|-----------------------------------"
    $lineas += "Ejemplo:"
    $lineas += "1.1.1.1  | Nombre del Proceso no incluyas el .exe | Organizacion     | Motivo del bloqueo     | Efectos si se bloquea"
    $lineas += " Lista blanca:"
    $lineas += " Formato: IP (una por linea)"
    $lineas += ""
    $lineas += "Efectos negativos si se bloquea una IP en lista negra que tiene anomalia ya sea de ruta o ips:"
    $lineas += " - Fallo en actualizaciones del sistema"
    $lineas += " - Problemas de activacion"
    $lineas += " - Fallos en apps que dependen de servicios en la nube"
    $lineas += ""
    $lineas += "Revisa anomalias en rutas"
    $lineas += "==============================================================="
    $lineas += ""

    $lineas | ForEach-Object { Add-Content -Encoding ASCII -Path $logFile -Value $_ }
}

# ============================ INICIO DEL SCRIPT ============================

$selfProcessId = $PID

# ✅ CARGA INICIAL DE EVENTOS REGISTRADOS (SOLO UNA VEZ)
if (Test-Path $loggedEventsFile) {
    $global:loggedEvents = Get-Content $loggedEventsFile -ErrorAction SilentlyContinue | Where-Object { $_ }
} else {
    $global:loggedEvents = @()
}

Cargar-Listas
EsPrimeraVez

# Registrar automáticamente el hash actual de Edge si es nuevo
$null = Registrar-HashEdgeSiNuevo

Write-Host "`nMonitoreando TODAS las conexiones salientes (excepto este script)..."
Write-Host "Presiona Ctrl+C para detener.`n"

while ($true) {
    Cargar-Listas
    $null = Registrar-HashEdgeSiNuevo

    $grupos = Obtener-ConexionesActivas
    $logCsvData = @()
    $logJsonData = @()

    foreach ($grupo in $grupos) {
        $procesoId = $grupo.Name
        if ($procesoId -eq $selfProcessId) { continue }

        try {
            $proc = Get-Process -Id $procesoId -ErrorAction Stop
            $exePath = $proc.Path
            $nombreProc = $proc.ProcessName
        } catch {
            continue
        }

        # Omitir Edge si es la ruta correcta y el hash es válido
        if ($exePath -eq $edgePath) {
            $hash = Obtener-Hash $exePath
            if (EsHashEdgeValido $hash) {
                continue
            }
        }

        $ips = $grupo.Group.RemoteAddress | Sort-Object -Unique

        foreach ($ip in $ips) {
            if (EsIPPuertaDeEnlace $ip) { continue }
            if ($whitelist -contains $ip) { continue }

            $ahora = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $geo = Obtener-GeolocalizacionIP $ip
            $linea = "$ahora [$nombreProc] IP:$ip Ruta:`"$exePath`" Ubi: $geo"

            # === 1. Bloquear si está en blacklist (por IP + proceso) ===
            $blacklistEntry = $global:blacklistData | Where-Object { $_.IP -eq $ip }
            if ($blacklistEntry) {
                $procesoCoincide = $false
                $entryActual = $null
                foreach ($entry in $blacklistEntry) {
                    if ($entry.Proceso -and $nombreProc) {
                        if ($entry.Proceso.ToLower() -eq $nombreProc.ToLower()) {
                            $procesoCoincide = $true
                            $entryActual = $entry
                            break
                        }
                    }
                }

                if ($procesoCoincide) {
                    $displayName = "BLACKLIST: [$($entryActual.Motivo)] - Proceso: $nombreProc - IP: $ip"
                    if (-not (Get-NetFirewallRule -DisplayName $displayName -ErrorAction SilentlyContinue)) {
                        New-NetFirewallRule -DisplayName $displayName -Description "Bloqueado por lista negra" `
                            -Direction Outbound -RemoteAddress $ip -Action Block -Protocol Any `
                            -Enabled True -Profile Any -ErrorAction SilentlyContinue
                    }

                    Write-Host "IP $ip bloqueada por lista negra (Proceso: $nombreProc)" -ForegroundColor DarkRed
                    $estado = "Bloqueada por lista negra"
                    Add-Content -Encoding ASCII -Path $logFile -Value "$linea => $estado"
                    continue
                }
            }

            # === 2. Bloquear si es desconocida ===
            if ($unknownlist -notcontains $ip) {
                Add-Content -Encoding ASCII -Path $unknownFile -Value $ip
            }

            $displayNameUnknown = "UNKNOWN: IP desconocida - Proceso: $nombreProc - IP: $ip"
            if (-not (Get-NetFirewallRule -DisplayName $displayNameUnknown -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -DisplayName $displayNameUnknown -Description "IP desconocida bloqueada" `
                    -Direction Outbound -RemoteAddress $ip -Action Block -Protocol Any `
                    -Enabled True -Profile Any -ErrorAction SilentlyContinue
            }

            # ✅ VERIFICACIÓN DEFINITIVA: ¿Ya está registrada esta IP + Proceso?
            $claveLog = "$ip-$nombreProc"
            $yaRegistrada = $false

            # Verificar en memoria RAM
            if ($global:loggedEvents -contains $claveLog) {
                $yaRegistrada = $true
            }
            # Verificar en disco (por si otro proceso lo agregó)
            elseif (Test-Path $loggedEventsFile) {
                if ((Get-Content $loggedEventsFile -ErrorAction SilentlyContinue) -contains $claveLog) {
                    $global:loggedEvents += $claveLog
                    $yaRegistrada = $true
                }
            }

            if (-not $yaRegistrada) {
                $estado = "Desconocida (bloqueada)"
                
                # Registrar en log de texto
                Add-Content -Encoding ASCII -Path $logFile -Value "$linea => $estado"
                Write-Host "$linea => $estado" -ForegroundColor Yellow

                # Agregar a CSV y JSON
                $logCsvData += [PSCustomObject]@{
                    Fecha     = $ahora
                    Proceso   = $nombreProc
                    IP        = $ip
                    Ruta      = $exePath
                    Ubicacion = $geo
                    Estado    = $estado
                }
                $logJsonData += [PSCustomObject]@{
                    Tiempo    = $ahora
                    Proceso   = $nombreProc
                    IP        = $ip
                    Ruta      = $exePath
                    Geo       = $geo
                    Estado    = $estado
                }

                # Registrar en memoria y en disco
                $global:loggedEvents += $claveLog
                $claveLog | Out-File -Append -Encoding ASCII $loggedEventsFile
            }
        }
    }

    # Guardar CSV
    if ($logCsvData.Count -gt 0) {
        if (-not (Test-Path $logCsvPath)) {
            $logCsvData | Export-Csv -Path $logCsvPath -Encoding UTF8 -NoTypeInformation
        } else {
            $logCsvData | Export-Csv -Path $logCsvPath -Encoding UTF8 -NoTypeInformation -Append
        }
    }

    # Guardar JSON
    if ($logJsonData.Count -gt 0) {
        $historicoJson = @()
        if (Test-Path $logJsonPath) {
            try {
                $contenido = Get-Content $logJsonPath -Raw
                if ($contenido.Trim().StartsWith("[")) {
                    $historicoJson = $contenido | ConvertFrom-Json
                    if ($historicoJson -isnot [array]) { $historicoJson = @($historicoJson) }
                }
            } catch { $historicoJson = @() }
        }
        $historicoJson += $logJsonData
        $historicoJson | ConvertTo-Json -Depth 5 | Out-File -Encoding UTF8 -FilePath $logJsonPath
    }

    Start-Sleep -Seconds 5
}