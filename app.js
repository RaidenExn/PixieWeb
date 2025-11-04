document.addEventListener('DOMContentLoaded', () => {
    // --- Theme Toggle Removed ---
    // All related elements, functions (setTheme), and listeners are gone.

    // --- Element Cache ---
    const wsStatusText = document.getElementById('ws-status-text');
    const wsStatusIcon = document.getElementById('ws-status-icon');
    const logContainer = document.getElementById('log-container');
    const clearLogBtn = document.getElementById('clear-log-btn');
    
    const scanBtn = document.getElementById('scan-btn');
    const scanBtnSpinner = document.getElementById('scan-btn-spinner');
    const scanBtnText = document.getElementById('scan-btn-text');
    const interfaceInput = document.getElementById('interface');
    
    const attackBtn = document.getElementById('attack-btn');
    const attackBtnSpinner = document.getElementById('attack-btn-spinner');
    const attackBtnText = document.getElementById('attack-btn-text');
    const stopBtn = document.getElementById('stop-btn');

    const targetListContainer = document.getElementById('target-list-container');
    const targetList = targetListContainer.querySelector('#target-list');
    const targetTable = targetListContainer.querySelector('#target-table');
    const targetPlaceholder = targetListContainer.querySelector('#target-placeholder');
    
    const targetBSSID = document.getElementById('target-bssid');
    const targetESSID = document.getElementById('target-essid');
    const attackTypeSelect = document.getElementById('attack-type');
    const pinGroup = document.getElementById('pin-group');
    const customPinInput = document.getElementById('custom-pin');
    const delayGroup = document.getElementById('delay-group');
    
    const credentialsList = document.getElementById('credentials-list');
    const credentialsPlaceholder = document.getElementById('credentials-placeholder');
    
    const manualBssidInput = document.getElementById('manual-bssid');
    const manualSetBtn = document.getElementById('manual-set-btn');
    const bssidRegex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;

    let selectedBSSID = null;
    let selectedESSID = null;
    let selectedModel = null;
    let ws;
    let selectedRow = null;

    // --- WebSocket Logic ---
    
    // M3: SVG icons for light theme
    const wsIconConnecting = `
        <svg class="icon" xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24" fill="currentColor" style="color: var(--status-yellow); animation: spin 1.5s linear infinite;">
          <path d="M480-160q-134 0-227-93t-93-227q0-134 93-227t227-93q69 0 132 28.5T720-690v-110h80v280H520v-80h168q-32-56-87.5-88T480-720q-100 0-170 70t-70 170q0 100 70 170t170 70q77 0 139-44t87-116h80q-27 106-114 173t-192 67Z"/>
        </svg>`;
    const wsIconConnected = `
        <svg class="icon" xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24" fill="currentColor" style="color: var(--status-green);">
          <path d="M480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm-21-203 294-294-56-56-238 238-124-124-56 56 180 180Z"/>
        </svg>`;
    const wsIconDisconnected = `
        <svg class="icon" xmlns="http://www.w3.org/2000/svg" height="24" viewBox="0 -960 960 960" width="24" fill="currentColor" style="color: var(--status-red);">
          <path d="M480-80q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-197q-54 54-127 85.5T480-80Zm-56-251L551-480l127-127-56-56-127 127-127-127-56 56 127 127-127 127 56 56Z"/>
        </svg>`;


    function connectWebSocket() {
        const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(`${proto}//${window.location.host}/ws`);
        updateWsStatus('Connecting...', wsIconConnecting);

        ws.onopen = () => {
            updateWsStatus('Connected', wsIconConnected);
            addLog('WebSocket connection established.', 'INFO');
        };

        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            if (data.type === 'log') {
                addLog(data.message, data.level);
            } else if (data.type === 'scan_results') {
                updateTargetList(data.networks);
            } else if (data.type === 'scan_complete') {
                setScanButtonState(false);
            } else if (data.type === 'attack_complete') {
                setAttackButtonState(false);
                if (data.success === true) {
                    addLog('Attack successful! Refreshing credentials...', 'INFO');
                    loadCredentials();
                }
            }
        };

        ws.onclose = () => {
            updateWsStatus('Disconnected', wsIconDisconnected);
            addLog('WebSocket disconnected. Attempting to reconnect in 3s...', 'ERROR');
            setScanButtonState(false);
            setAttackButtonState(false);
            setTimeout(connectWebSocket, 3000);
        };

        ws.onerror = () => {
            updateWsStatus('Error', wsIconDisconnected);
            addLog('WebSocket error.', 'ERROR');
        };
    }

    // --- UI Helper Functions ---
    function updateWsStatus(text, icon) {
        wsStatusText.textContent = text;
        wsStatusIcon.innerHTML = icon;
    }

    function addLog(message, level = 'DEBUG') {
        const logEntry = document.createElement('div');
        const timestamp = new Date().toLocaleTimeString();
        const cleanMessage = message.replace(/\x1b\[[0-9;]*m/g, ''); // Strip ANSI colors
        logEntry.className = `log-${level.toUpperCase()}`;
        logEntry.textContent = `[${timestamp}] ${cleanMessage}`;
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight;
    }

    // Returns semantic CSS classes
    function getSignalColor(pwr) {
        if (pwr > -60) return 'signal-strong';
        if (pwr > -75) return 'signal-medium';
        return 'signal-weak';
    }
    
    // Returns semantic CSS classes
    function getStatusLabel(status) {
        const labels = {
            'vulnerable_model': { class: 'status-vulnerable', text: '[VULNERABLE]' },
            'wps_locked': { class: 'status-locked', text: '[LOCKED]' },
            'vulnerable_version': { class: 'status-warning', text: '[WPS 1.0]' },
            'already_stored': { class: 'status-info', text: '[STORED]' }
        };
        const s = labels[status];
        if (s) {
            return `<span class="status-label ${s.class}">${s.text}</span>`;
        }
        return '<span class="status-label status-default">N/A</span>';
    }

    function updateTargetList(networks) {
        targetList.innerHTML = ''; // Clear old results
        if (networks && networks.length > 0) {
            targetPlaceholder.classList.add('hidden');
            targetTable.classList.remove('hidden');
            
            networks.forEach(net => {
                const row = document.createElement('tr');
                row.className = 'table-row'; // Custom class for interactivity
                
                const pwrColor = getSignalColor(net.Level);
                const model = `${net.Model} ${net.Model_number}`.trim();
                const essid = net.ESSID || '(No ESSID)';

                row.innerHTML = `
                    <td class="table-cell">${getStatusLabel(net.status)}</td>
                    <td class="table-cell" title="${essid}">${essid}</td>
                    <td class="table-cell font-mono">${net.BSSID}</td>
                    <td class="table-cell ${pwrColor}">${net.Level} dBm</td>
                    <td class="table-cell">${net.WPS_version}</td>
                    <td class="table-cell">${net.WPS_locked ? 'Yes' : 'No'}</td>
                    <td class="table-cell" title="${model}">${model || 'N/A'}</td>
                    <td class="table-cell action-cell"></td>
                `;
                
                const selectBtn = document.createElement('button');
                selectBtn.textContent = 'Select';
                selectBtn.className = 'btn btn-tonal btn-small';
                selectBtn.onclick = (e) => {
                    e.stopPropagation();
                    selectTarget(net.BSSID, net.ESSID, model, row);
                };
                
                row.cells[row.cells.length - 1].appendChild(selectBtn);
                row.addEventListener('click', () => selectTarget(net.BSSID, net.ESSID, model, row));
                targetList.appendChild(row);
            });
        } else {
            targetPlaceholder.classList.remove('hidden');
            targetTable.classList.add('hidden');
            targetPlaceholder.textContent = 'No WPS networks found.';
        }
    }

    function selectTarget(bssid, essid, model, rowElement) {
        if (!stopBtn.classList.contains('hidden')) {
            addLog('Cannot select a new target while an attack is in progress.', 'WARNING');
            return; 
        }
    
        selectedBSSID = bssid;
        selectedESSID = essid || '(No ESSID)';
        selectedModel = model || null;
        
        targetBSSID.textContent = selectedBSSID;
        targetESSID.textContent = selectedESSID;
        
        attackBtn.disabled = false;
        attackBtnText.textContent = 'Start Attack';

        if (selectedRow) {
            selectedRow.classList.remove('selected-row');
        }
        
        if(rowElement) {
            rowElement.classList.add('selected-row');
            selectedRow = rowElement;
        }

        addLog(`Target selected: ${selectedESSID} (${selectedBSSID})`, 'INFO');
    }

    function setScanButtonState(isLoading) {
        scanBtn.disabled = isLoading;
        scanBtnSpinner.classList.toggle('hidden', !isLoading);
        scanBtnText.textContent = isLoading ? 'Scanning...' : 'Scan';
    }
    
    function setAttackButtonState(isLoading) {
        attackBtn.disabled = isLoading;
        scanBtn.disabled = isLoading;
        manualSetBtn.disabled = isLoading;
        manualBssidInput.disabled = isLoading;
        
        targetListContainer.classList.toggle('opacity-50', isLoading);
        targetListContainer.classList.toggle('pointer-events-none', isLoading);

        attackBtnSpinner.classList.toggle('hidden', !isLoading);
        attackBtnText.textContent = isLoading ? 'Attacking...' : 'Start Attack';
        stopBtn.classList.toggle('hidden', !isLoading);
    }
    
    async function loadCredentials() {
        try {
            const response = await fetch('/api/credentials');
            if (!response.ok) throw new Error('Failed to fetch credentials');
            const creds = await response.json();
            
            credentialsList.innerHTML = ''; // Clear old
            if (creds && creds.length > 0) {
                credentialsPlaceholder.classList.add('hidden');
                creds.reverse().forEach(cred => {
                    const row = document.createElement('tr');
                    row.innerHTML = `
                        <td class="table-cell" title="${cred.essid}">${cred.essid}</td>
                        <td class="table-cell font-mono">${cred.pin}</td>
                        <td class="table-cell font-mono" title="${cred.psk}">${cred.psk}</td>
                    `;
                    credentialsList.appendChild(row);
                });
            } else {
                credentialsPlaceholder.classList.remove('hidden');
            }
        } catch (err) {
            addLog(`Error loading credentials: ${err.message}`, 'ERROR');
        }
    }

    // --- Event Listeners ---
    clearLogBtn.onclick = () => { logContainer.innerHTML = ''; };

    scanBtn.onclick = () => {
        const interfaceVal = interfaceInput.value;
        if (!interfaceVal) {
            addLog('Interface name cannot be empty.', 'ERROR'); return;
        }
        localStorage.setItem('PixieWeb_interface', interfaceVal);
        
        addLog(`Starting scan on ${interfaceVal}...`, 'INFO');
        setScanButtonState(true);
        targetPlaceholder.textContent = 'Scanning...';
        targetPlaceholder.classList.remove('hidden');
        targetTable.classList.add('hidden');
        
        fetch(`/api/scan?interface=${interfaceVal}`, { method: 'POST' })
            .catch(err => {
                addLog(`Scan API call failed: ${err}`, 'ERROR');
                setScanButtonState(false);
            });
    };

    attackTypeSelect.onchange = () => {
        const type = attackTypeSelect.value;
        pinGroup.classList.toggle('hidden', type !== 'pin' && type !== 'bruteforce');
        delayGroup.classList.toggle('hidden', type !== 'bruteforce');
        
        if (type === 'pin') {
            customPinInput.placeholder = "e.g., 12345670 (blank for auto)";
        } else if (type === 'bruteforce') {
            customPinInput.placeholder = "Start PIN e.g., 0000 (blank for new)";
        }
    };

    attackBtn.onclick = () => {
        if (!selectedBSSID) {
            addLog('No target selected for attack.', 'ERROR'); return;
        }
        setAttackButtonState(true);

        const attackSettings = {
            interface: interfaceInput.value,
            bssid: selectedBSSID,
            essid: selectedESSID,
            model: selectedModel,
            attackType: attackTypeSelect.value,
            pin: customPinInput.value || null,
            delay: parseFloat(document.getElementById('bruteforce-delay').value) || 1.0,
            write: document.getElementById('check-write').checked,
            save: document.getElementById('check-save').checked,
            showPixieCmd: document.getElementById('check-pixie-cmd').checked,
            pixieForce: document.getElementById('check-pixie-force').checked,
            add_to_vuln_list: document.getElementById('check-add-vuln').checked
        };
        
        if (attackSettings.pin === null && attackSettings.attackType === 'pin') {
            addLog('PIN Attack selected, but no PIN provided. Using auto-generated PIN.', 'WARNING');
        }

        addLog(`Starting ${attackSettings.attackType} attack on ${attackSettings.bssid}...`, 'INFO');

        fetch('/api/attack', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(attackSettings)
        })
        .catch(err => {
            addLog(`Attack API call failed: ${err}`, 'ERROR');
            setAttackButtonState(false);
        });
    };
    
    stopBtn.onclick = () => {
        addLog('Sending stop signal to server...', 'WARNING');
        fetch('/api/attack/stop', { method: 'POST' })
            .catch(err => addLog(`Stop API call failed: ${err}`, 'ERROR'));
    };
    
    manualSetBtn.onclick = () => {
        if (!stopBtn.classList.contains('hidden')) {
            addLog('Cannot set manual target while an attack is in progress.', 'WARNING');
            return;
        }
        
        const bssid = manualBssidInput.value.trim().toUpperCase();
        if (!bssid) {
            addLog('Manual BSSID cannot be empty.', 'ERROR'); return;
        }
        if (!bssidRegex.test(bssid)) {
            addLog('Invalid BSSID format. Use AA:BB:CC:11:22:33.', 'ERROR'); return;
        }
        
        if (selectedRow) selectedRow.classList.remove('selected-row');
        selectTarget(bssid, '(Manual Target)', null, null);
    };

    // --- Initial Load ---
    const savedInterface = localStorage.getItem('PixieWeb_interface');
    if (savedInterface) {
        interfaceInput.value = savedInterface;
    }
    connectWebSocket();
    loadCredentials();
});