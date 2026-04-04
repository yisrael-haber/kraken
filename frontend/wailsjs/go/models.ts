export namespace main {
	
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
	export class AdoptIPAddressRequest {
	    label: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	
	    static createFrom(source: any = {}) {
	        return new AdoptIPAddressRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.interfaceName = source["interfaceName"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	    }
	}
	export class AdoptedIPAddress {
	    label: string;
	    ip: string;
	    interfaceName: string;
	    mac: string;
	
	    static createFrom(source: any = {}) {
	        return new AdoptedIPAddress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.ip = source["ip"];
	        this.interfaceName = source["interfaceName"];
	        this.mac = source["mac"];
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
	export class AdoptedIPAddressDetails {
	    label: string;
	    ip: string;
	    interfaceName: string;
	    mac: string;
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
	
	export class InterfaceAddress {
	    family: string;
	    address: string;
	    ip?: string;
	    netmask?: string;
	    broadcast?: string;
	    peer?: string;
	
	    static createFrom(source: any = {}) {
	        return new InterfaceAddress(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.family = source["family"];
	        this.address = source["address"];
	        this.ip = source["ip"];
	        this.netmask = source["netmask"];
	        this.broadcast = source["broadcast"];
	        this.peer = source["peer"];
	    }
	}
	export class NetworkInterface {
	    name: string;
	    description?: string;
	    index?: number;
	    mtu?: number;
	    hardwareAddr?: string;
	    osFlags?: string[];
	    captureFlags?: string[];
	    rawCaptureFlags?: number;
	    captureVisible: boolean;
	    captureOnly: boolean;
	    canAdopt: boolean;
	    adoptionIssue?: string;
	    isUp: boolean;
	    isRunning: boolean;
	    isLoopback: boolean;
	    isPointToPoint: boolean;
	    supportsMulticast: boolean;
	    systemAddresses?: InterfaceAddress[];
	    captureAddresses?: InterfaceAddress[];
	
	    static createFrom(source: any = {}) {
	        return new NetworkInterface(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.description = source["description"];
	        this.index = source["index"];
	        this.mtu = source["mtu"];
	        this.hardwareAddr = source["hardwareAddr"];
	        this.osFlags = source["osFlags"];
	        this.captureFlags = source["captureFlags"];
	        this.rawCaptureFlags = source["rawCaptureFlags"];
	        this.captureVisible = source["captureVisible"];
	        this.captureOnly = source["captureOnly"];
	        this.canAdopt = source["canAdopt"];
	        this.adoptionIssue = source["adoptionIssue"];
	        this.isUp = source["isUp"];
	        this.isRunning = source["isRunning"];
	        this.isLoopback = source["isLoopback"];
	        this.isPointToPoint = source["isPointToPoint"];
	        this.supportsMulticast = source["supportsMulticast"];
	        this.systemAddresses = this.convertValues(source["systemAddresses"], InterfaceAddress);
	        this.captureAddresses = this.convertValues(source["captureAddresses"], InterfaceAddress);
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
	export class InterfaceSnapshot {
	    interfaces: NetworkInterface[];
	    captureWarning?: string;
	
	    static createFrom(source: any = {}) {
	        return new InterfaceSnapshot(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.interfaces = this.convertValues(source["interfaces"], NetworkInterface);
	        this.captureWarning = source["captureWarning"];
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
	
	    static createFrom(source: any = {}) {
	        return new PingAdoptedIPAddressRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sourceIP = source["sourceIP"];
	        this.targetIP = source["targetIP"];
	        this.count = source["count"];
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
	export class StoredAdoptionConfiguration {
	    label: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	
	    static createFrom(source: any = {}) {
	        return new StoredAdoptionConfiguration(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.label = source["label"];
	        this.interfaceName = source["interfaceName"];
	        this.ip = source["ip"];
	        this.mac = source["mac"];
	    }
	}
	export class UpdateAdoptedIPAddressRequest {
	    label: string;
	    currentIP: string;
	    interfaceName: string;
	    ip: string;
	    mac?: string;
	
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
	    }
	}

}

