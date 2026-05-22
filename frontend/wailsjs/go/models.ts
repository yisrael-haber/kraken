export namespace adoption {
	
	export class Identity {
	    label: string;
	    ip: number[];
	    interfaceName: string;
	    mac?: number[];
	    subnetMask?: number[];
	    defaultGateway?: number[];
	    mtu?: number;
	
	    static createFrom(source: any = {}) {
	        return new Identity(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.ip = source["ip"];
	        this.interfaceName = source["interfaceName"];
	        this.mac = source["mac"];
	        this.subnetMask = source["subnetMask"];
	        this.defaultGateway = source["defaultGateway"];
	        this.mtu = source["mtu"];
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
	    ip: number[];
	    interfaceName: string;
	    mac?: number[];
	    subnetMask?: number[];
	    defaultGateway?: number[];
	    mtu?: number;
	    currentIP: string;
	
	    static createFrom(source: any = {}) {
	        return new UpdateAdoptedIPAddressRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.ip = source["ip"];
	        this.interfaceName = source["interfaceName"];
	        this.mac = source["mac"];
	        this.subnetMask = source["subnetMask"];
	        this.defaultGateway = source["defaultGateway"];
	        this.mtu = source["mtu"];
	        this.currentIP = source["currentIP"];
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

export namespace buffer {
	
	export class Buffer {
	
	
	    static createFrom(source: any = {}) {
	        return new Buffer(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	
	    }
	}

}

export namespace interfaces {
	
	export class InterfaceOption {
	    name: string;
	
	    static createFrom(source: any = {}) {
	        return new InterfaceOption(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
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

export namespace net {
	
	export class Interface {
	    Index: number;
	    MTU: number;
	    Name: string;
	    HardwareAddr: number[];
	    Flags: number;
	
	    static createFrom(source: any = {}) {
	        return new Interface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.Index = source["Index"];
	        this.MTU = source["MTU"];
	        this.Name = source["Name"];
	        this.HardwareAddr = source["HardwareAddr"];
	        this.Flags = source["Flags"];
	    }
	}

}

export namespace operations {
	
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

}

export namespace storage {
	
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
	export class StoredAdoptionConfiguration {
	    label: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	    subnetMask?: string;
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
	        this.subnetMask = source["subnetMask"];
	        this.defaultGateway = source["defaultGateway"];
	        this.mtu = source["mtu"];
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

