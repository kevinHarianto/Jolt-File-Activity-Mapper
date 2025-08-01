// Log Parser Engine for Security Log Analysis - ELK
class ElkLogParser {
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
        console.log(`Parsing ${files.length} files in ${format} format using ElkLogParser`);

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
        if (format === 'elk') {
            this.parseELKLogs(content);
        } else {
            console.warn(`ElkLogParser received an unsupported format: ${format}`);
        }
    }

    // --- ELK Log Parsing ---
    parseELKLogs(content) {
        console.log("Parsing ELK logs");
        let events = [];
        try {
            // Try parsing as a single JSON array (e.g., from a file export)
            events = JSON.parse(content);
            if (!Array.isArray(events)) {
                // If it's a single object, wrap it in an array
                events = [events];
            }
        } catch (e) {
            // If that fails, try parsing as line-delimited JSON (common for streaming)
            try {
                events = content.trim().split('\n').map(line => JSON.parse(line));
            } catch (error) {
                console.error("Error parsing ELK content as JSON or line-delimited JSON:", error);
                return;
            }
        }

        events.forEach(log => {
            // ELK often wraps the original log in a '_source' field. Use it if it exists.
            const event = log._source || log;
            this.processGenericEvent(event);
        });
    }

    // This method heuristically parses a generic event object by checking for common field names
    processGenericEvent(event) {
        const timestamp = event['@timestamp'] || event.UtcTime || new Date().toISOString();

        // Check for Process Creation (Sysmon/Defender/ECS like fields)
        const processImage = event.Image || event.process?.executable || event.InitiatingProcessFileName;
        const processId = event.ProcessId || event.process?.pid || event.InitiatingProcessId;
        if (processImage && processId) {
            const processName = processImage.split('\\').pop().split('/').pop();
            this.parsedData.processes.push({
                timestamp: timestamp,
                processId: processId,
                parentProcessId: event.ParentProcessId || event.process?.parent?.pid || event.InitiatingProcessParentId,
                image: processImage,
                commandLine: event.CommandLine || event.process?.command_line || event.InitiatingProcessCommandLine,
                user: event.User || event.user?.name || event.UserName,
                processName: processName
            });
        }

        // Check for Network Connection (Sysmon/ECS like fields)
        const destIp = event.DestinationIp || event.destination?.ip;
        const sourceIp = event.SourceIp || event.source?.ip;
        if (destIp) {
            const processImageForConn = event.Image || event.process?.executable;
            const processNameForConn = processImageForConn ? processImageForConn.split('\\').pop().split('/').pop() : 'N/A';
            this.parsedData.networkConnections.push({
                timestamp: timestamp,
                sourceIp: sourceIp,
                sourcePort: event.SourcePort || event.source?.port,
                destinationIp: destIp,
                destinationPort: event.DestinationPort || event.destination?.port,
                protocol: event.Protocol || event.network?.protocol,
                processId: event.ProcessId || event.process?.pid,
                image: processImageForConn,
                user: event.User || event.user?.name,
                processName: processNameForConn
            });
        }

        // Check for File Activity (Sysmon/ECS like fields)
        const filePath = event.TargetFilename || event.file?.path;
        if (filePath) {
            const processImageForFile = event.Image || event.process?.executable;
            const processNameForFile = processImageForFile ? processImageForFile.split('\\').pop().split('/').pop() : 'N/A';
            let action = 'File Activity';
            if (event.EventID === 11) action = 'File Created';
            else if (event.EventID === 23) action = 'File Deleted';
            else if (event.event?.action) action = event.event.action;

            this.parsedData.fileActivities.push({
                timestamp: timestamp,
                filePath: filePath,
                action: action,
                activityType: action,
                processId: event.ProcessId || event.process?.pid,
                image: processImageForFile,
                user: event.User || event.user?.name,
                processName: processNameForFile
            });
        }

        // Check for DNS Query (Sysmon/ECS like fields)
        const dnsQuery = event.QueryName || event.dns?.question?.name;
        if (dnsQuery) {
            const processImageForDns = event.Image || event.process?.executable;
            const processNameForDns = processImageForDns ? processImageForDns.split('\\').pop().split('/').pop() : 'N/A';
            this.parsedData.dnsQueries.push({
                timestamp: timestamp,
                queryName: dnsQuery,
                queryResults: event.QueryResults || (event.dns?.answers ? event.dns.answers.map(a => a.data).join(', ') : 'N/A'),
                processId: event.ProcessId || event.process?.pid,
                image: processImageForDns,
                user: event.User || event.user?.name,
                processName: processNameForDns
            });
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
