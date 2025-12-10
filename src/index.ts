#!/usr/bin/env node

import * as core from '@actions/core'
import { Bytes, Identifier, MerkleTree, NULL_TOPIC, PrivateKey, Reference, Signature, Span } from '@ethersphere/bee-js'
import { Arrays, Binary, Chunk, Strings, Types } from 'cafe-utility'
import { argv, env } from 'process'

interface SOC {
    payload: Bytes
    signature: Signature
    address: Reference
}

// required flags
const payload = Arrays.requireStringArgument(argv, 'payload', env, 'MKSOC_PAYLOAD')
const feedType = Arrays.requireStringArgument(argv, 'feed-type', env, 'MKSOC_FEED_TYPE')

if (!['v1', 'v2'].includes(feedType)) {
    throw new Error(`Invalid feed type: ${feedType}. Allowed values are 'v1' and 'v2'.`)
}

// optional flags
const privateKey = new PrivateKey(
    Types.asHexString(Arrays.getArgument(argv, 'private-key', env, 'MKSOC_PRIVATE_KEY') ?? Strings.randomHex(64), {
        name: 'private-key',
        byteLength: 32
    })
)
const topic = new Identifier(
    Types.asHexString(Arrays.getArgument(argv, 'topic', env, 'MKSOC_TOPIC') ?? NULL_TOPIC.toHex(), {
        name: 'topic',
        byteLength: 32
    })
)

main()

async function main() {
    let socCac: Chunk
    if (feedType === 'v1') {
        const cac = await MerkleTree.root(new TextEncoder().encode(payload))
        socCac = await MerkleTree.root(
            Binary.concatBytes(Binary.numberToUint64(BigInt(Math.floor(Date.now() / 1000)), 'BE'), cac.hash())
        )
    } else {
        socCac = await MerkleTree.root(new TextEncoder().encode(payload))
    }
    const soc = makeSingleOwnerChunk(socCac, privateKey, topic)
    core.setOutput('mksoc_result_signature', soc.signature.toHex())
    core.setOutput('mksoc_result_payload', soc.payload.toHex())
    core.setOutput('mksoc_result_topic', topic.toHex())
    core.setOutput('mksoc_result_owner', privateKey.publicKey().address().toHex())
}

function makeSingleOwnerChunk(chunk: Chunk, signer: PrivateKey, identifier: Identifier): SOC {
    const address = new Reference(
        Binary.keccak256(Binary.concatBytes(identifier.toUint8Array(), signer.publicKey().address().toUint8Array()))
    )
    const signature = signer.sign(Binary.concatBytes(identifier.toUint8Array(), chunk.hash()))
    const cacPayload = chunk.build().slice(0, Number(chunk.span) + Span.LENGTH)

    const span = Span.fromSlice(cacPayload, 0)
    const payload = Bytes.fromSlice(cacPayload, Span.LENGTH)

    return {
        payload: new Bytes(Binary.concatBytes(span.toUint8Array(), payload.toUint8Array())),
        signature,
        address
    }
}
