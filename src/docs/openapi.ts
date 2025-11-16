export const openapiSpec = {
    openapi: '3.0.3',
    info: {
        title: 'KMS API',
        version: '0.1.0',
        description:
            'Demo KMS with RSA-OAEP session key exchange and AES-256-GCM. Use TLS in production. Authenticate via X-Client-Token with active session.',
    },
    servers: [{ url: 'http://localhost:{port}', variables: { port: { default: '3000' } } }],
    components: {
        securitySchemes: {
            ClientToken: { type: 'apiKey', in: 'header', name: 'X-Client-Token' },
        },
        schemas: {
            Error: {
                type: 'object',
                properties: {
                    error: {
                        type: 'object',
                        properties: {
                            code: { type: 'string' },
                            message: { type: 'string' },
                            details: {},
                        },
                        required: ['code', 'message'],
                    },
                },
                required: ['error'],
            },
        },
    },
    paths: {
        '/health': {
            get: {
                summary: 'Health check',
                responses: { '200': { description: 'OK' } },
            },
        },
        '/session/init': {
            get: {
                summary: 'Get RSA public key and sessionId',
                responses: {
                    '200': {
                        description: 'Init info',
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        data: {
                                            type: 'object',
                                            properties: {
                                                sessionId: { type: 'string' },
                                                rsaPublicKeyPem: { type: 'string' },
                                            },
                                            required: ['sessionId', 'rsaPublicKeyPem'],
                                        },
                                    },
                                    required: ['data'],
                                },
                            },
                        },
                    },
                },
            },
        },
        '/session/key-exchange': {
            post: {
                summary: 'Exchange RSA-wrapped AES session key',
                parameters: [
                    { in: 'header', name: 'X-Client-Token', required: true, schema: { type: 'string' } },
                ],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    sessionId: { type: 'string' },
                                    wrappedKey: { type: 'string', description: 'base64 RSA-OAEP(SHA-256) wrapped 32-byte AES key' },
                                },
                                required: ['sessionId', 'wrappedKey'],
                            },
                        },
                    },
                },
                responses: {
                    '200': { description: 'Session accepted' },
                    '400': { description: 'Bad request', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
                    '401': { description: 'Unauthorized', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
                },
            },
        },
        '/crypto/encrypt': {
            post: {
                summary: 'Encrypt with session AES-256-GCM',
                security: [{ ClientToken: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    algorithm: { type: 'string', enum: ['AES-256-GCM'] },
                                    plaintext: { type: 'string', description: 'base64' },
                                    aad: { type: 'string', description: 'base64', nullable: true },
                                },
                                required: ['algorithm', 'plaintext'],
                            },
                        },
                    },
                },
                responses: {
                    '200': { description: 'Ciphertext with iv and tag' },
                    '429': { description: 'Rate limited', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
                },
            },
        },
        '/crypto/decrypt': {
            post: {
                summary: 'Decrypt with session AES-256-GCM',
                security: [{ ClientToken: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    algorithm: { type: 'string', enum: ['AES-256-GCM'] },
                                    ciphertext: { type: 'string', description: 'base64' },
                                    iv: { type: 'string', description: 'base64' },
                                    tag: { type: 'string', description: 'base64' },
                                    aad: { type: 'string', description: 'base64', nullable: true },
                                },
                                required: ['algorithm', 'ciphertext', 'iv', 'tag'],
                            },
                        },
                    },
                },
                responses: {
                    '200': { description: 'Plaintext base64' },
                    '429': { description: 'Rate limited', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
                },
            },
        },
        '/keys/generate': {
            post: {
                summary: 'Generate new data key',
                security: [{ ClientToken: [] }],
                responses: { '201': { description: 'Key created' }, '429': { description: 'Rate limited' } },
            },
        },
        '/keys/rotate': {
            post: {
                summary: 'Rotate active key version',
                security: [{ ClientToken: [] }],
                requestBody: {
                    required: true,
                    content: { 'application/json': { schema: { type: 'object', properties: { keyId: { type: 'string' } }, required: ['keyId'] } } },
                },
                responses: { '200': { description: 'Rotated' }, '429': { description: 'Rate limited' } },
            },
        },
        '/keys/{keyId}': {
            get: {
                summary: 'Get key metadata',
                security: [{ ClientToken: [] }],
                parameters: [{ in: 'path', name: 'keyId', required: true, schema: { type: 'string' } }],
                responses: { '200': { description: 'Metadata' }, '404': { description: 'Not found' }, '429': { description: 'Rate limited' } },
            },
        },
        '/keys/wrap': {
            post: {
                summary: 'Wrap plaintext with stored key version',
                security: [{ ClientToken: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    keyId: { type: 'string' },
                                    version: { type: 'integer' },
                                    plaintext: { type: 'string', description: 'base64' },
                                },
                                required: ['keyId', 'version', 'plaintext'],
                            },
                        },
                    },
                },
                responses: { '200': { description: 'Wrapped ciphertext' }, '404': { description: 'Not found' } },
            },
        },
        '/keys/unwrap': {
            post: {
                summary: 'Unwrap ciphertext with stored key version',
                security: [{ ClientToken: [] }],
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    keyId: { type: 'string' },
                                    version: { type: 'integer' },
                                    ciphertext: { type: 'string', description: 'base64' },
                                    iv: { type: 'string', description: 'base64' },
                                    tag: { type: 'string', description: 'base64' },
                                },
                                required: ['keyId', 'version', 'ciphertext', 'iv', 'tag'],
                            },
                        },
                    },
                },
                responses: { '200': { description: 'Plaintext' }, '404': { description: 'Not found' } },
            },
        },
    },
} as const;
