// Log Parser Engine for Security Log Analysis - Sysmon
class SysmonLogParser {
    constructor() {
        this.parsedData = {
            processes: [],
            networkConnections: [],
            fileActivities: [],
            dllActivities: [],
            registryChanges: [],
            userActivities: [],
            threats: [],
            dnsQueries: []
        };
    }

    // Main parsing function
    async parseLogs(files, format) {
        console.log(`Parsing ${files.length} files in ${format} format using SysmonLogParser`);

        // Clear parsedData for new analysis
        this.parsedData = {
            processes: [], networkConnections: [], fileActivities: [],
            dllActivities: [], registryChanges: [], userActivities: [],
            threats: [], dnsQueries: []
        };

        for (let file of files) {
            const content = await this.readFile(file);
            await this.parseByFormat(content, format);
        }

        return this.generateVisualizationData();
    }

    // Read file content
    async readFile(file) {
        return new Promise((resolve) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.readAsText(file);
        });
    }

    // Parse based on format
    async parseByFormat(content, format) {
        if (format === 'sysmon') {
            this.parseSysmonLogs(content);
        } else {
            console.warn(`SysmonLogParser received an unsupported format: ${format}`);
        }
    }

    // --- Sysmon Log Parsing ---
    parseSysmonLogs(content) {
        console.log("Parsing Sysmon logs");
        try {
            const events = JSON.parse(content);
            if (Array.isArray(events)) {
                events.forEach(event => this.processSysmonEvent(event));
            } else {
                console.error("Sysmon log content is not a JSON array:", content);
            }
        } catch (error) {
            console.error("Error parsing Sysmon content as JSON:", error);
        }
    }

    processSysmonEvent(event) {
        if (event.EventID === 1) this.processProcessCreation(event);
        else if (event.EventID === 3) this.processNetworkConnection(event);
        else if (event.EventID === 11 || event.EventID === 23 || event.EventID === 15) this.processFileActivity(event);
        else if (event.EventID === 22) this.processDnsQuery(event);
    }

    processProcessCreation(event) {
        const processName = event.Image ? event.Image.split('\\').pop() : 'N/A';
        this.parsedData.processes.push({
            timestamp: event.UtcTime || new Date().toISOString(),
            processId: event.ProcessId,
            parentProcessId: event.ParentProcessId,
            image: event.Image,
            commandLine: event.CommandLine,
            user: event.User,
            processName: processName
        });
    }

    processNetworkConnection(event) {
        const processName = event.Image ? event.Image.split('\\').pop() : 'N/A';
        this.parsedData.networkConnections.push({
            timestamp: event.UtcTime || new Date().toISOString(),
            sourceIp: event.SourceIp,
            sourcePort: event.SourcePort,
            destinationIp: event.DestinationIp,
            destinationPort: event.DestinationPort,
            protocol: event.Protocol,
            processId: event.ProcessId,
            image: event.Image,
            user: event.User,
            processName: processName
        });
    }

    processFileActivity(event) {
        let action = '';
        switch (event.EventID) {
            case 11: action = 'File Created'; break;
            case 23: action = 'File Deleted'; break;
            case 15: action = 'File Stream Created'; break;
            default: action = `EventID ${event.EventID}`;
        }
        const processName = event.Image ? event.Image.split('\\').pop() : 'N/A';
        this.parsedData.fileActivities.push({
            timestamp: event.UtcTime || new Date().toISOString(),
            filePath: event.TargetFilename,
            action: action,
            activityType: action,
            processId: event.ProcessId,
            image: event.Image,
            user: event.User,
            processName: processName
        });
    }

    processDnsQuery(event) {
        const processName = event.Image ? event.Image.split('\\').pop() : 'N/A';
        this.parsedData.dnsQueries.push({
            timestamp: event.UtcTime || new Date().toISOString(),
            queryName: event.QueryName,
            queryResults: event.QueryResults,
            processId: event.ProcessId,
            image: event.Image,
            user: event.User,
            processName: processName
        });
    }

    // Consolidate data for visualization
    generateVisualizationData() {
        const visualization = {
            aptPatterns: { threatIndicators: [], attackChain: [] },
            fileMap: { fileActivities: [] },
            networkMap: { connections: [], dnsQueries: [] }
        };
        let step = 1;

        this.parsedData.networkConnections.forEach(conn => {
            const processName = conn.processName || 'N/A';
            if (!this.isInternalIP(conn.destinationIp)) {
                visualization.aptPatterns.threatIndicators.push(`Command and Control Connection: Outbound connection to C2 IP: ${conn.destinationIp}:${conn.destinationPort} (Process: ${processName})`);
                visualization.aptPatterns.attackChain.push(`${step++}. Command and Control (C2): Suspicious network connection to ${conn.destinationIp}:${conn.destinationPort} from ${processName}`);
            } else if (this.isInternalIP(conn.destinationIp) && conn.destinationPort === 445) {
                visualization.aptPatterns.threatIndicators.push(`Lateral Movement - SMB: Internal SMB connection: ${conn.sourceIp} -> ${conn.destinationIp} (Process: ${processName})`);
                visualization.aptPatterns.attackChain.push(`${step++}. Lateral Movement: Internal SMB connection from ${conn.sourceIp} to ${conn.destinationIp}`);
            }
            visualization.networkMap.connections.push({ ...conn, process: processName });
        });

        this.parsedData.fileActivities.forEach(file => {
            const processName = file.processName || 'N/A';
            if (file.action === 'File Created' && file.filePath.includes('Temp')) {
                visualization.aptPatterns.threatIndicators.push(`Exfiltration Staging: File created in temp for potential exfiltration: ${file.filePath} (Process: ${processName}) (User: ${file.user})`);
                visualization.aptPatterns.attackChain.push(`${step++}. Exfiltration: Data staged for exfiltration via ${file.filePath}`);
            } else if (file.action === 'File Deleted') {
                visualization.aptPatterns.threatIndicators.push(`Evidence Tampering: File Deleted: ${file.filePath} (Process: ${processName}) (User: ${file.user})`);
                visualization.aptPatterns.attackChain.push(`${step++}. Evidence Tampering: File ${file.filePath} deleted`);
            }
            visualization.fileMap.fileActivities.push({ ...file, process: processName });
        });
        
        visualization.networkMap.dnsQueries = this.parsedData.dnsQueries.map(dns => ({ ...dns, process: dns.processName }));

        return visualization;
    }

    isInternalIP(ip) {
        if (!ip) return false;
        if (ip === '127.0.0.1' || ip === '::1') return true;
        const parts = ip.split('.');
        if (parts.length === 4) {
            const p1 = parseInt(parts[0], 10);
            const p2 = parseInt(parts[1], 10);
            if (p1 === 10) return true;
            if (p1 === 172 && p2 >= 16 && p2 <= 31) return true;
            if (p1 === 192 && p2 === 168) return true;
        }
        return false;
    }
}
