export namespace adoption {
	
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
	    mtu?: number;
	
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
	        this.mtu = source["mtu"];
	    }
	}
	export class AdoptedIPAddress {
	    label: string;
	    ip: string;
	    interfaceName: string;
	    mac: string;
	    defaultGateway?: string;
	    mtu?: number;
	
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
	        this.mtu = source["mtu"];
	    }
	}
	export class ServiceSummaryItem {
	    label: string;
	    value: string;
	    code?: boolean;
	
	    static createFrom(source: any = {}) {
	        return new ServiceSummaryItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.value = source["value"];
	        this.code = source["code"];
	    }
	}
	export class ServiceStatus {
	    service: string;
	    active: boolean;
	    port: number;
	    config?: Record<string, string>;
	    summary?: ServiceSummaryItem[];
	    startedAt?: string;
	    lastError?: string;
	    scriptError?: ScriptRuntimeError;
	
	    static createFrom(source: any = {}) {
	        return new ServiceStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.service = source["service"];
	        this.active = source["active"];
	        this.port = source["port"];
	        this.config = source["config"];
	        this.summary = this.convertValues(source["summary"], ServiceSummaryItem);
	        this.startedAt = source["startedAt"];
	        this.lastError = source["lastError"];
	        this.scriptError = this.convertValues(source["scriptError"], ScriptRuntimeError);
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
	export class PacketRecordingStatus {
	    active: boolean;
	    outputPath?: string;
	    startedAt?: string;
	    lastError?: string;
	
	    static createFrom(source: any = {}) {
	        return new PacketRecordingStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.active = source["active"];
	        this.outputPath = source["outputPath"];
	        this.startedAt = source["startedAt"];
	        this.lastError = source["lastError"];
	    }
	}
	export class ScriptRuntimeError {
	    scriptName?: string;
	    surface?: string;
	    stage?: string;
	    direction?: string;
	    lastError?: string;
	    updatedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new ScriptRuntimeError(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.scriptName = source["scriptName"];
	        this.surface = source["surface"];
	        this.stage = source["stage"];
	        this.direction = source["direction"];
	        this.lastError = source["lastError"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class CaptureStatus {
	    activeFilter?: string;
	    pendingFilter?: string;
	    lastError?: string;
	    updatedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new CaptureStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.activeFilter = source["activeFilter"];
	        this.pendingFilter = source["pendingFilter"];
	        this.lastError = source["lastError"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class AdoptedIPAddressDetails {
	    label: string;
	    ip: string;
	    interfaceName: string;
	    mac: string;
	    defaultGateway?: string;
	    mtu?: number;
	    transportScriptName?: string;
	    applicationScriptName?: string;
	    capture?: CaptureStatus;
	    scriptError?: ScriptRuntimeError;
	    recording?: PacketRecordingStatus;
	    services?: ServiceStatus[];
	    arpCacheEntries?: ARPCacheItem[];
	
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
	        this.mtu = source["mtu"];
	        this.transportScriptName = source["transportScriptName"];
	        this.applicationScriptName = source["applicationScriptName"];
	        this.capture = this.convertValues(source["capture"], CaptureStatus);
	        this.scriptError = this.convertValues(source["scriptError"], ScriptRuntimeError);
	        this.recording = this.convertValues(source["recording"], PacketRecordingStatus);
	        this.services = this.convertValues(source["services"], ServiceStatus);
	        this.arpCacheEntries = this.convertValues(source["arpCacheEntries"], ARPCacheItem);
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
	export class ResolveDNSAdoptedIPAddressRequest {
	    sourceIP: string;
	    server: string;
	    name: string;
	    type?: string;
	    transport?: string;
	    timeoutMillis?: number;
	
	    static createFrom(source: any = {}) {
	        return new ResolveDNSAdoptedIPAddressRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sourceIP = source["sourceIP"];
	        this.server = source["server"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.transport = source["transport"];
	        this.timeoutMillis = source["timeoutMillis"];
	    }
	}
	export class ResolveDNSAdoptedIPAddressResult {
	    sourceIP: string;
	    server: string;
	    name: string;
	    type: string;
	    transport: string;
	    rttMillis?: number;
	    responseID?: number;
	    responseCode?: string;
	    records?: string[];
	
	    static createFrom(source: any = {}) {
	        return new ResolveDNSAdoptedIPAddressResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sourceIP = source["sourceIP"];
	        this.server = source["server"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.transport = source["transport"];
	        this.rttMillis = source["rttMillis"];
	        this.responseID = source["responseID"];
	        this.responseCode = source["responseCode"];
	        this.records = source["records"];
	    }
	}
	
	export class ServiceFieldOption {
	    value: string;
	    label: string;
	
	    static createFrom(source: any = {}) {
	        return new ServiceFieldOption(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.value = source["value"];
	        this.label = source["label"];
	    }
	}
	export class ServiceFieldDefinition {
	    name: string;
	    label: string;
	    type: string;
	    required?: boolean;
	    defaultValue?: string;
	    placeholder?: string;
	    scriptSurface?: string;
	    options?: ServiceFieldOption[];
	
	    static createFrom(source: any = {}) {
	        return new ServiceFieldDefinition(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.label = source["label"];
	        this.type = source["type"];
	        this.required = source["required"];
	        this.defaultValue = source["defaultValue"];
	        this.placeholder = source["placeholder"];
	        this.scriptSurface = source["scriptSurface"];
	        this.options = this.convertValues(source["options"], ServiceFieldOption);
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
	export class ServiceDefinition {
	    service: string;
	    label: string;
	    defaultPort?: number;
	    fields?: ServiceFieldDefinition[];
	
	    static createFrom(source: any = {}) {
	        return new ServiceDefinition(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.service = source["service"];
	        this.label = source["label"];
	        this.defaultPort = source["defaultPort"];
	        this.fields = this.convertValues(source["fields"], ServiceFieldDefinition);
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
	export class StartAdoptedIPAddressServiceRequest {
	    ip: string;
	    service: string;
	    config?: Record<string, string>;
	
	    static createFrom(source: any = {}) {
	        return new StartAdoptedIPAddressServiceRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.service = source["service"];
	        this.config = source["config"];
	    }
	}
	export class StopAdoptedIPAddressServiceRequest {
	    ip: string;
	    service: string;
	
	    static createFrom(source: any = {}) {
	        return new StopAdoptedIPAddressServiceRequest(source);
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
	    mtu?: number;
	
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
	        this.mtu = source["mtu"];
	    }
	}
	export class UpdateAdoptedIPAddressScriptsRequest {
	    ip: string;
	    transportScriptName: string;
	    applicationScriptName: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateAdoptedIPAddressScriptsRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.ip = source["ip"];
	        this.transportScriptName = source["transportScriptName"];
	        this.applicationScriptName = source["applicationScriptName"];
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
	    surface: string;
	    source: string;
	
	    static createFrom(source: any = {}) {
	        return new SaveStoredScriptRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.surface = source["surface"];
	        this.source = source["source"];
	    }
	}
	export class StoredScript {
	    name: string;
	    surface: string;
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
	        this.surface = source["surface"];
	        this.source = source["source"];
	        this.available = source["available"];
	        this.compileError = source["compileError"];
	        this.updatedAt = source["updatedAt"];
	    }
	}
	export class StoredScriptRef {
	    name: string;
	    surface: string;
	
	    static createFrom(source: any = {}) {
	        return new StoredScriptRef(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.surface = source["surface"];
	    }
	}
	export class StoredScriptSummary {
	    name: string;
	    surface: string;
	    available: boolean;
	    compileError?: string;
	    updatedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new StoredScriptSummary(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.surface = source["surface"];
	        this.available = source["available"];
	        this.compileError = source["compileError"];
	        this.updatedAt = source["updatedAt"];
	    }
	}

}

export namespace storage {
	
	export class StoredAdoptionConfiguration {
	    label: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	    defaultGateway?: string;
	    mtu?: number;
	
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
	        this.mtu = source["mtu"];
	    }
	}
	export class StoredRoute {
	    label: string;
	    destinationCIDR: string;
	    viaAdoptedIP: string;
	    transportScriptName?: string;
	
	    static createFrom(source: any = {}) {
	        return new StoredRoute(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.destinationCIDR = source["destinationCIDR"];
	        this.viaAdoptedIP = source["viaAdoptedIP"];
	        this.transportScriptName = source["transportScriptName"];
	    }
	}

}

