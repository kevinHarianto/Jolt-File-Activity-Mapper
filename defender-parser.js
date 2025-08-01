// Log Parser Engine for Security Log Analysis - Defender
class DefenderLogParser {
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
        console.log(`Parsing ${files.length} files in ${format} format using DefenderLogParser`);

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
        if (format === 'defender') {
            this.parseDefenderLogs(content);
        } else {
            console.warn(`DefenderLogParser received an unsupported format: ${format}`);
        }
    }

    // --- Defender Log Parsing ---
    parseDefenderLogs(content) {
        console.log("Parsing Defender logs");
        try {
            const events = JSON.parse(content);
            if (Array.isArray(events)) {
                events.forEach(event => {
                    const timestamp = event.TimeGenerated || new Date().toISOString();
                    const processName = event.InitiatingProcessFileName || 'N/A';
                    const user = event.UserName || 'N/A';

                    if (event.EventType === "ProcessCreated") {
                        this.parsedData.processes.push({
                            timestamp, processId: event.InitiatingProcessId, parentProcessId: event.InitiatingProcessParentId,
                            image: event.InitiatingProcessFileName, commandLine: event.InitiatingProcessCommandLine, user, processName
                        });
                    } else if (event.EventType === "NetworkConnection") {
                        this.parsedData.networkConnections.push({
                            timestamp, sourceIp: event.SourceIp, sourcePort: event.SourcePort, destinationIp: event.DestinationIp,
                            destinationPort: event.DestinationPort, protocol: event.Protocol, processId: event.InitiatingProcessId,
                            image: event.InitiatingProcessFileName, user, processName
                        });
                    } else if (event.EventType === "FileCreated" || event.EventType === "FileDeleted") {
                        this.parsedData.fileActivities.push({
                            timestamp, filePath: event.FileName || event.FolderPath,
                            action: event.EventType === "FileCreated" ? "File Created" : "File Deleted", activityType: event.EventType,
                            processId: event.InitiatingProcessId, image: event.InitiatingProcessFileName, user, processName
                        });
                    } else if (event.EventType === "DnsQuery") {
                        this.parsedData.dnsQueries.push({
                            timestamp, queryName: event.QueryName, queryResults: event.QueryResults,
                            processId: event.InitiatingProcessId, image: event.InitiatingProcessFileName, user, processName
                        });
                    } else if (event.EventType === "Detection") {
                        this.parsedData.threats.push({
                            timestamp, threatName: event.ThreatName, severity: event.Severity, filePath: event.FileName || event.FolderPath,
                            processName: event.InitiatingProcessFileName || processName, description: event.ThreatName, type: 'defender_detection'
                        });
                    } else if (event.EventType === "RegistryValueSet") {
                        this.parsedData.registryChanges.push({
                            timestamp, key: event.RegistryKey, valueName: event.RegistryValueName, valueData: event.RegistryValueData,
                            processId: event.InitiatingProcessId, image: event.InitiatingProcessFileName, user, processName
                        });
                    }
                });
            } else {
                console.error("Defender log content is not a JSON array:", content);
            }
        } catch (error) {
            console.error("Error parsing Defender content as JSON:", error);
        }
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
            }
            visualization.networkMap.connections.push({ ...conn, process: processName });
        });

        this.parsedData.fileActivities.forEach(file => {
            const processName = file.processName || 'N/A';
            if (file.action === 'File Created' && file.filePath.includes('Temp')) {
                visualization.aptPatterns.threatIndicators.push(`Exfiltration Staging: File created in temp: ${file.filePath} (Process: ${processName})`);
                visualization.aptPatterns.attackChain.push(`${step++}. Exfiltration: Data staged in ${file.filePath}`);
            }
            visualization.fileMap.fileActivities.push({ ...file, process: processName });
        });
        
        visualization.aptPatterns.threatIndicators.push(...this.parsedData.threats.map(t => ({
            threatName: t.threatName,
            description: t.description,
            processName: t.processName,
            severity: t.severity
        })));
        
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
