export namespace adoption {
	
	export class Identity {
	    label: string;
	    ip: number[];
	    interfaceName: string;
	    mac?: number[];
	    subnetPrefix?: number;
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
	        this.subnetPrefix = source["subnetPrefix"];
	        this.defaultGateway = source["defaultGateway"];
	        this.mtu = source["mtu"];
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
	
	export class Selection {
	    options: string[];
	    warning?: string;
	
	    static createFrom(source: any = {}) {
	        return new Selection(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.options = source["options"];
	        this.warning = source["warning"];
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
	
	export class DNSRecord {
	    section: string;
	    name: string;
	    type: string;
	    class: string;
	    ttl: number;
	    value: string;
	
	    static createFrom(source: any = {}) {
	        return new DNSRecord(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.section = source["section"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.class = source["class"];
	        this.ttl = source["ttl"];
	        this.value = source["value"];
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
	    records?: DNSRecord[];
	
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
	        this.records = this.convertValues(source["records"], DNSRecord);
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

export namespace storage {
	
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
	export class StoredAdoptionConfiguration {
	    label: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	    subnetPrefix?: number;
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
	        this.subnetPrefix = source["subnetPrefix"];
	        this.defaultGateway = source["defaultGateway"];
	        this.mtu = source["mtu"];
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

