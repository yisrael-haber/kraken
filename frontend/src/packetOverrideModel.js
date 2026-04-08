export const PACKET_OVERRIDE_SCHEMA = [
    {
        layer: 'Ethernet',
        fields: [
            {name: 'SrcMAC', type: 'text', placeholder: '02:00:00:00:00:77', note: 'Override the Ethernet source MAC.'},
            {name: 'DstMAC', type: 'text', placeholder: 'ff:ff:ff:ff:ff:ff', note: 'Override the Ethernet destination MAC.'},
        ],
    },
    {
        layer: 'IPv4',
        fields: [
            {name: 'SrcIP', type: 'text', placeholder: '192.168.56.77', note: 'Override the IPv4 source address.'},
            {name: 'DstIP', type: 'text', placeholder: '192.168.56.1', note: 'Override the IPv4 destination address.'},
            {name: 'TTL', type: 'number', placeholder: '64', note: 'Override the IPv4 TTL value.'},
            {name: 'TOS', type: 'number', placeholder: '0', note: 'Override the IPv4 TOS / DSCP byte.'},
            {name: 'Id', type: 'number', placeholder: '0', note: 'Override the IPv4 identification field.'},
        ],
    },
    {
        layer: 'ARP',
        fields: [
            {name: 'Operation', type: 'number', placeholder: '1', note: 'Override the ARP operation code.'},
            {name: 'SourceHwAddress', type: 'text', placeholder: '02:00:00:00:00:77', note: 'Override the ARP sender MAC.'},
            {name: 'SourceProtAddress', type: 'text', placeholder: '192.168.56.77', note: 'Override the ARP sender IP.'},
            {name: 'DstHwAddress', type: 'text', placeholder: '00:00:00:00:00:00', note: 'Override the ARP target MAC.'},
            {name: 'DstProtAddress', type: 'text', placeholder: '192.168.56.1', note: 'Override the ARP target IP.'},
        ],
    },
    {
        layer: 'ICMPv4',
        fields: [
            {name: 'TypeCode', type: 'select', options: ['EchoRequest', 'EchoReply'], note: 'Override the ICMP type/code pair.'},
            {name: 'Id', type: 'number', placeholder: '1', note: 'Override the ICMP identifier.'},
            {name: 'Seq', type: 'number', placeholder: '1', note: 'Override the ICMP sequence value.'},
        ],
    },
];

export function createEmptyAdoptedOverrideBindings() {
    return {
        arpRequestOverride: '',
        arpRequestScript: '',
        arpReplyOverride: '',
        arpReplyScript: '',
        icmpEchoRequestOverride: '',
        icmpEchoRequestScript: '',
        icmpEchoReplyOverride: '',
        icmpEchoReplyScript: '',
    };
}

export function defaultOverrideFieldValue(field) {
    if (field.type === 'number') {
        return '0';
    }
    if (field.type === 'select') {
        return field.options?.[0] || '';
    }
    return '';
}

export function createPacketOverrideEditor(override = null) {
    const editor = {
        name: override?.name || '',
        layers: {},
    };

    for (const section of PACKET_OVERRIDE_SCHEMA) {
        editor.layers[section.layer] = {};
        for (const field of section.fields) {
            const rawValue = override?.layers?.[section.layer]?.[field.name];
            editor.layers[section.layer][field.name] = {
                enabled: rawValue !== undefined && rawValue !== null && rawValue !== '',
                value: rawValue !== undefined && rawValue !== null ? String(rawValue) : '',
            };
        }
    }

    return editor;
}

export function buildStoredPacketOverridePayload(editor) {
    const layers = {};

    for (const section of PACKET_OVERRIDE_SCHEMA) {
        const layerPayload = {};

        for (const field of section.fields) {
            const draft = editor.layers?.[section.layer]?.[field.name];
            if (!draft?.enabled) {
                continue;
            }

            if (field.type === 'number') {
                const value = String(draft.value ?? '').trim();
                if (!value) {
                    throw new Error(`${section.layer}.${field.name} requires a value.`);
                }

                const parsed = Number.parseInt(value, 10);
                if (!Number.isInteger(parsed)) {
                    throw new Error(`${section.layer}.${field.name} must be an integer.`);
                }

                layerPayload[field.name] = parsed;
                continue;
            }

            const value = String(draft.value ?? '').trim();
            if (!value) {
                throw new Error(`${section.layer}.${field.name} requires a value.`);
            }

            layerPayload[field.name] = value;
        }

        if (Object.keys(layerPayload).length) {
            layers[section.layer] = layerPayload;
        }
    }

    if (!Object.keys(layers).length) {
        throw new Error('Enable at least one layer field before saving a packet override.');
    }

    return {
        name: String(editor.name || '').trim(),
        layers,
    };
}
