// Log Parser Engine for Security Log Analysis - Wazuh
class WazuhLogParser {
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
        console.log(`Parsing ${files.length} files in ${format} format using WazuhLogParser`);

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
        if (format === 'wazuh') {
            this.parseWazuhLogs(content);
        } else {
            console.warn(`WazuhLogParser received an unsupported format: ${format}`);
        }
    }

    // --- Wazuh Log Parsing ---
    parseWazuhLogs(content) {
        console.log("Parsing Wazuh logs");
        try {
            const alerts = JSON.parse(content);
            if (Array.isArray(alerts)) {
                alerts.forEach(alert => {
                    const timestamp = alert.timestamp || new Date().toISOString();
                    const rule = alert.rule || {};
                    const data = alert.data || {};

                    // Create a threat indicator from the Wazuh rule
                    if (rule.id && rule.description) {
                        this.parsedData.threats.push({
                            timestamp: timestamp,
                            threatName: rule.description,
                            rule: rule.id,
                            severity: this.mapWazuhLevel(rule.level),
                            description: alert.full_log || rule.description,
                            type: 'wazuh_alert',
                            processName: data.audit?.event?.process?.name || data.command || 'N/A'
                        });
                    }

                    // Specifically parse file integrity monitoring events
                    if (data.audit?.event?.file && data.audit?.event?.action) {
                        const event = data.audit.event;
                        this.parsedData.fileActivities.push({
                            timestamp: timestamp,
                            filePath: event.file,
                            action: event.action,
                            activityType: `wazuh-fim-${event.action}`,
                            processId: event.process?.pid,
                            image: event.process?.name,
                            user: event.user,
                            processName: event.process?.name || 'N/A'
                        });
                    }
                    // Add other parsers for different Wazuh decoders as needed
                });
            } else {
                console.error("Wazuh log content is not a JSON array:", content);
            }
        } catch (error) {
            console.error("Error parsing Wazuh content as JSON:", error);
        }
    }
    
    // Maps Wazuh's numeric level to a severity string
    mapWazuhLevel(level) {
        if (!level) return 'low';
        if (level >= 12) return 'high';
        if (level >= 7) return 'medium';
        if (level >= 3) return 'low';
        return 'informational'; // Levels below 3
    }


    // Consolidate data for visualization
    generateVisualizationData() {
        const visualization = {
            aptPatterns: { threatIndicators: [], attackChain: [] },
            fileMap: { fileActivities: [] },
            networkMap: { connections: [], dnsQueries: [] }
        };
        let step = 1;
        
        // Add threats from Wazuh alerts
        this.parsedData.threats.forEach(t => {
            visualization.aptPatterns.threatIndicators.push({
                threatName: t.threatName,
                description: t.description,
                processName: t.processName,
                severity: t.severity
            });
            visualization.aptPatterns.attackChain.push(`${step++}. ${t.threatName}: ${t.description}`);
        });

        this.parsedData.fileActivities.forEach(file => {
            const processName = file.processName || 'N/A';
            visualization.fileMap.fileActivities.push({ ...file, process: processName });
        });

        this.parsedData.networkConnections.forEach(conn => {
            const processName = conn.processName || 'N/A';
            visualization.networkMap.connections.push({ ...conn, process: processName });
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
