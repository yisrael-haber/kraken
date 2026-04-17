export namespace adoption {
	
	export class ARPActivity {
	    timestamp: string;
	    direction: string;
	    event: string;
	    peerIP?: string;
	    peerMAC?: string;
	    details?: string;
	
	    static createFrom(source: any = {}) {
	        return new ARPActivity(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.direction = source["direction"];
	        this.event = source["event"];
	        this.peerIP = source["peerIP"];
	        this.peerMAC = source["peerMAC"];
	        this.details = source["details"];
	    }
	}
	export class ARPCacheItem {
	    ip: string;
	    mac: string;
	    updatedAt: string;
	
	    static createFrom(source: any = {}) {
	        return new ARPCacheItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class AdoptIPAddressRequest {
	    label: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	    defaultGateway?: string;
	
	    static createFrom(source: any = {}) {
	        return new AdoptIPAddressRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.interfaceName = source["interfaceName"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.defaultGateway = source["defaultGateway"];
	    }
	}
	export class AdoptedIPAddress {
	    label: string;
	    ip: string;
	    interfaceName: string;
	    mac: string;
	    defaultGateway?: string;
	
	    static createFrom(source: any = {}) {
	        return new AdoptedIPAddress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.ip = source["ip"];
	        this.interfaceName = source["interfaceName"];
	        this.mac = source["mac"];
	        this.defaultGateway = source["defaultGateway"];
	    }
	}
	export class ICMPActivity {
	    timestamp: string;
	    direction: string;
	    event: string;
	    peerIP?: string;
	    id?: number;
	    sequence?: number;
	    rttMillis?: number;
	    status?: string;
	    details?: string;
	
	    static createFrom(source: any = {}) {
	        return new ICMPActivity(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.timestamp = source["timestamp"];
	        this.direction = source["direction"];
	        this.event = source["event"];
	        this.peerIP = source["peerIP"];
	        this.id = source["id"];
	        this.sequence = source["sequence"];
	        this.rttMillis = source["rttMillis"];
	        this.status = source["status"];
	        this.details = source["details"];
	    }
	}
	export class TCPServiceStatus {
	    service: string;
	    active: boolean;
	    port: number;
	    rootDirectory?: string;
	    useTLS: boolean;
	    startedAt?: string;
	    lastError?: string;
	
	    static createFrom(source: any = {}) {
	        return new TCPServiceStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.service = source["service"];
	        this.active = source["active"];
	        this.port = source["port"];
	        this.rootDirectory = source["rootDirectory"];
	        this.useTLS = source["useTLS"];
	        this.startedAt = source["startedAt"];
	        this.lastError = source["lastError"];
	    }
	}
	export class PacketRecordingStatus {
	    active: boolean;
	    outputPath?: string;
	    startedAt?: string;
	    packetCount?: number;
	    byteCount?: number;
	    lastError?: string;
	
	    static createFrom(source: any = {}) {
	        return new PacketRecordingStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.active = source["active"];
	        this.outputPath = source["outputPath"];
	        this.startedAt = source["startedAt"];
	        this.packetCount = source["packetCount"];
	        this.byteCount = source["byteCount"];
	        this.lastError = source["lastError"];
	    }
	}
	export class AdoptedIPAddressDetails {
	    label: string;
	    ip: string;
	    interfaceName: string;
	    mac: string;
	    defaultGateway?: string;
	    scriptName?: string;
	    recording?: PacketRecordingStatus;
	    tcpServices?: TCPServiceStatus[];
	    arpCacheEntries?: ARPCacheItem[];
	    arpEvents?: ARPActivity[];
	    icmpEvents?: ICMPActivity[];
	
	    static createFrom(source: any = {}) {
	        return new AdoptedIPAddressDetails(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.ip = source["ip"];
	        this.interfaceName = source["interfaceName"];
	        this.mac = source["mac"];
	        this.defaultGateway = source["defaultGateway"];
	        this.scriptName = source["scriptName"];
	        this.recording = this.convertValues(source["recording"], PacketRecordingStatus);
	        this.tcpServices = this.convertValues(source["tcpServices"], TCPServiceStatus);
	        this.arpCacheEntries = this.convertValues(source["arpCacheEntries"], ARPCacheItem);
	        this.arpEvents = this.convertValues(source["arpEvents"], ARPActivity);
	        this.icmpEvents = this.convertValues(source["icmpEvents"], ICMPActivity);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	export class PingAdoptedIPAddressReply {
	    sequence: number;
	    success: boolean;
	    rttMillis?: number;
	
	    static createFrom(source: any = {}) {
	        return new PingAdoptedIPAddressReply(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sequence = source["sequence"];
	        this.success = source["success"];
	        this.rttMillis = source["rttMillis"];
	    }
	}
	export class PingAdoptedIPAddressRequest {
	    sourceIP: string;
	    targetIP: string;
	    count?: number;
	    payloadHex?: string;
	
	    static createFrom(source: any = {}) {
	        return new PingAdoptedIPAddressRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sourceIP = source["sourceIP"];
	        this.targetIP = source["targetIP"];
	        this.count = source["count"];
	        this.payloadHex = source["payloadHex"];
	    }
	}
	export class PingAdoptedIPAddressResult {
	    sourceIP: string;
	    targetIP: string;
	    sent: number;
	    received: number;
	    replies: PingAdoptedIPAddressReply[];
	
	    static createFrom(source: any = {}) {
	        return new PingAdoptedIPAddressResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sourceIP = source["sourceIP"];
	        this.targetIP = source["targetIP"];
	        this.sent = source["sent"];
	        this.received = source["received"];
	        this.replies = this.convertValues(source["replies"], PingAdoptedIPAddressReply);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class StartAdoptedIPAddressRecordingRequest {
	    ip: string;
	    outputPath?: string;
	
	    static createFrom(source: any = {}) {
	        return new StartAdoptedIPAddressRecordingRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.outputPath = source["outputPath"];
	    }
	}
	export class StartAdoptedIPAddressTCPServiceRequest {
	    ip: string;
	    service: string;
	    port: number;
	    rootDirectory?: string;
	    useTLS: boolean;
	
	    static createFrom(source: any = {}) {
	        return new StartAdoptedIPAddressTCPServiceRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.service = source["service"];
	        this.port = source["port"];
	        this.rootDirectory = source["rootDirectory"];
	        this.useTLS = source["useTLS"];
	    }
	}
	export class StopAdoptedIPAddressTCPServiceRequest {
	    ip: string;
	    service: string;
	
	    static createFrom(source: any = {}) {
	        return new StopAdoptedIPAddressTCPServiceRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.service = source["service"];
	    }
	}
	
	export class UpdateAdoptedIPAddressRequest {
	    label: string;
	    currentIP: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	    defaultGateway?: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateAdoptedIPAddressRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.currentIP = source["currentIP"];
	        this.interfaceName = source["interfaceName"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.defaultGateway = source["defaultGateway"];
	    }
	}
	export class UpdateAdoptedIPAddressScriptRequest {
	    ip: string;
	    scriptName: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateAdoptedIPAddressScriptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.scriptName = source["scriptName"];
	    }
	}

}

export namespace config {
	
	export class StoredAdoptionConfiguration {
	    label: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	    defaultGateway?: string;
	
	    static createFrom(source: any = {}) {
	        return new StoredAdoptionConfiguration(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.interfaceName = source["interfaceName"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	        this.defaultGateway = source["defaultGateway"];
	    }
	}

}

export namespace interfaces {
	
	export class InterfaceOption {
	    name: string;
	    canAdopt: boolean;
	
	    static createFrom(source: any = {}) {
	        return new InterfaceOption(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.canAdopt = source["canAdopt"];
	    }
	}
	export class Selection {
	    options: InterfaceOption[];
	    warning?: string;
	
	    static createFrom(source: any = {}) {
	        return new Selection(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.options = this.convertValues(source["options"], InterfaceOption);
	        this.warning = source["warning"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace script {
	
	export class SaveStoredScriptRequest {
	    name: string;
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new SaveStoredScriptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.source = source["source"];
	    }
	}
	export class StoredScript {
	    name: string;
	    source: string;
	    available: boolean;
	    compileError?: string;
	    updatedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new StoredScript(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.source = source["source"];
	        this.available = source["available"];
	        this.compileError = source["compileError"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class StoredScriptSummary {
	    name: string;
	    available: boolean;
	    compileError?: string;
	    updatedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new StoredScriptSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.available = source["available"];
	        this.compileError = source["compileError"];
	        this.updatedAt = source["updatedAt"];
	    }
	}

}

