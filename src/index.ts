/**
 * FreeSignal Protocol
 * 
 * Copyright (C) 2025  Christian Braghette
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>
 */

import { LocalStorage, Crypto } from "@freesignal/interfaces";
import { FreeSignalAPI } from "@freesignal/protocol/api";
import { KeySession } from "@freesignal/protocol/double-ratchet";
import { Datagram, IdentityKeys, UserId } from "@freesignal/protocol/types";
import { decodeBase64, numberFromUint8Array } from '@freesignal/utils';
import crypto from '@freesignal/crypto'

const FREESIGNAL_MIME = "application/x-freesignal";

type DatagramId = string;

export function createClient(opts: {
    relayUrl: string;
    secretSignKey: Uint8Array<ArrayBufferLike>;
    secretBoxKey: Uint8Array;
    sessions: LocalStorage<UserId, KeySession>;
    keyExchange: LocalStorage<string, Crypto.KeyPair>;
    users: LocalStorage<UserId, IdentityKeys>;
}) {
    return new FreeSignalClient(opts);
}

class FreeSignalClient extends FreeSignalAPI {
    public readonly relayUrl: string;

    public constructor(opts: {
        relayUrl: string;
        secretSignKey: Uint8Array<ArrayBufferLike>;
        secretBoxKey: Uint8Array;
        sessions: LocalStorage<UserId, KeySession>;
        keyExchange: LocalStorage<string, Crypto.KeyPair>;
        users: LocalStorage<UserId, IdentityKeys>;
    }) {
        super(opts);
        this.relayUrl = opts.relayUrl;
    }

    public async getDatagrams(publicKey: string | Uint8Array, url?: string): Promise<Datagram[]> {
        const res = await fetch(url ?? this.relayUrl, {
            method: 'GET',
            headers: {
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey))
            }
        })
        return this.unpackDatagrams(await this.decryptData(await res.bytes(), FreeSignalClient.getUserId(publicKey)));
    }

    public async postDatagrams(datagrams: Datagram[], publicKey: string | Uint8Array, url?: string): Promise<number> {
        const data = await this.encryptData(this.packDatagrams(datagrams), FreeSignalClient.getUserId(publicKey));
        const res = await fetch(url ?? this.relayUrl, {
            method: 'POST',
            headers: {
                'Content-Type': FREESIGNAL_MIME,
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey))
            },
            body: data.encode() as any
        });
        return numberFromUint8Array(await this.decryptData(await res.bytes(), FreeSignalClient.getUserId(publicKey)));
    }

    public async deleteDatagrams(datagramIds: DatagramId[], publicKey: string | Uint8Array, url?: string): Promise<number> {
        const data = await this.encryptData(datagramIds.map(datagramId => crypto.UUID.parse(datagramId)).reduce((prev, curr) => new Uint8Array([...prev, ...curr]), new Uint8Array()), FreeSignalClient.getUserId(publicKey));
        const res = await fetch(url ?? this.relayUrl, {
            method: 'DELETE',
            headers: {
                'Content-Type': FREESIGNAL_MIME,
                authorization: this.createToken(publicKey instanceof Uint8Array ? publicKey : decodeBase64(publicKey))
            },
            body: data.encode() as any
        });
        return numberFromUint8Array(await this.decryptData(await res.bytes(), FreeSignalClient.getUserId(publicKey)));
    }
}