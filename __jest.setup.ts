import { TextDecoder, TextEncoder } from 'util';

Object.assign(global, { TextDecoder, TextEncoder });

const crypto = require('crypto').webcrypto;

// Shims the crypto property onto global
global.crypto = crypto;

import 'jsdom-global/register';
