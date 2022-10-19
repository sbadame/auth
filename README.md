**WARNING: This is just a hobby project of mine, it has not been security reviewed.**
_Seriously, it barely works..._

# ACLs for URLs!

This server authenticates users and applies ACLs to urls.

Only Google Sign In is supported.


## How it works

This auth server runs on Cloud Run on a tailnet with my home server.

I have a public domain that points to the Cloud Run instance so all URLs are accesible from the public internet.


```
                 ┌────────────────────────────────────┐
                 │              Tailnet               │
                 │                                    │
External HTTPS───┼─►Auth Server────HTTP───►Home Server│
                 │   │      ▲                         │
                 │   │      │                         │
                 └───┼──────┼─────────────────────────┘
                     │      │
                     ▼      │
                 Auth user with Google
```

### Typical flow.

The Auth server is an HTTP server.

When a request comes in for a URL `/honeypot` the Auth server redirects the request to `/login&target=honeypot`.

Once on the `/login` page, the user is prompted to login. Once the user is authorized by Google, then a cookie `id_token` is set for the domain.

The user is then redirected back to the `target` URL.

The Auth server again sees the URL, but now with the cookie set. The Auth server verifies the JWT in the cookie extracts the username and checks if it matches the ACL.

## Future work

* Support webauthN.
* Support having different ACLs for different users.
* Support changing ACLs without a server reboot.
* Support using the backend to store the ACLs so that the frontend can stay stateless.

### WebAuthn

#### https://webauthn.bin.coffee/

##### Create Credential

```
Contacting token... please perform your verification gesture (e.g., touch it, or plug it in)

Note: Raw response in console.

:: "None" Attestation Format ::
[PASS] Calculated RP ID hash must match what the browser derived.: pkLSG3xtVeHOI8U5mCjSx0m_am7y_gPMnhDN9O1TCIs == pkLSG3xtVeHOI8U5mCjSx0m_am7y_gPMnhDN9O1TCIs
[PASS] User presence and Attestation Object must both be set: 65 == 65
[PASS] Credential ID from CBOR and Raw ID match: dca62528be5e324a77c67106127173e9677b4dca1e447e05355180eb5be9225a33d869a915710d6373a6963d4cb533b3344787d722ac893c5ac48dd41c6245e0 == dca62528be5e324a77c67106127173e9677b4dca1e447e05355180eb5be9225a33d869a915710d6373a6963d4cb533b3344787d722ac893c5ac48dd41c6245e0
Keypair Identifier: dca62528be5e324a77c67106127173e9677b4dca1e447e05355180eb5be9225a33d869a915710d6373a6963d4cb533b3344787d722ac893c5ac48dd41c6245e0
Public Key: 0466aa570313fa4f6aab0cfa69ac9620002b005a20f5c1595485631aaf171837ff1216ae03a4ffd709a1c6f55f9ab9a56cb1045bd16fff5fef6aa698172ec35f7c

:: CBOR Attestation Object Data ::
RP ID Hash: a642d21b7c6d55e1ce23c5399828d2c749bf6a6ef2fe03cc9e10cdf4ed53088b
Counter: 00000004 Flags: 65
AAGUID: 00000000000000000000000000000000

:: Client Data Information ::
Client Data object, in full:
{
  "type": "webauthn.create",
  "challenge": "owfQuBCzHaPh_R5jeCL-PQ",
  "origin": "https://webauthn.bin.coffee",
  "crossOrigin": false,
  "other_keys_can_be_added_here": "do not compare clientDataJSON against a template. See https://goo.gl/yabPex"
}

[PASS] Challenge matches: owfQuBCzHaPh_R5jeCL-PQ == owfQuBCzHaPh_R5jeCL-PQ
[PASS] ClientData.origin matches this origin (WD-06): https://webauthn.bin.coffee == https://webauthn.bin.coffee
[PASS] Type is valid (WD-08): webauthn.create == webauthn.create


Raw request:
{
  "challenge": {
    "0": 163,
    "1": 7,
    "2": 208,
    "3": 184,
    "4": 16,
    "5": 179,
    "6": 29,
    "7": 163,
    "8": 225,
    "9": 253,
    "10": 30,
    "11": 99,
    "12": 120,
    "13": 34,
    "14": 254,
    "15": 61
  },
  "rp": {
    "name": "Acme"
  },
  "user": {
    "id": {
      "0": 49,
      "1": 48,
      "2": 57,
      "3": 56,
      "4": 50,
      "5": 51,
      "6": 55,
      "7": 50,
      "8": 51,
      "9": 53,
      "10": 52,
      "11": 48,
      "12": 57,
      "13": 56,
      "14": 55,
      "15": 50
    },
    "name": "john.p.smith@example.com",
    "displayName": "John P. Smith",
    "icon": "https://pics.acme.com/00/p/aBjjjpqPb.png"
  },
  "pubKeyCredParams": [
    {
      "alg": -7,
      "type": "public-key"
    }
  ],
  "authenticatorSelection": {
    "authenticatorAttachment": "cross-platform",
    "requireResidentKey": false,
    "userVerification": "preferred"
  },
  "timeout": 60000,
  "excludeCredentials": [],
  "extensions": {
    "exts": true
  }
}

Failures: 0 TODOs: 0
```

### Get Assertion

```
Contacting token... please perform your verification gesture (e.g., touch it, or plug it in)

Raw response in console.
[PASS] Challenge is identical: sV99dakT1k2k9-aFWNJBkA == sV99dakT1k2k9-aFWNJBkA
[PASS] ClientData.origin matches this origin (WD-06): https://webauthn.bin.coffee == https://webauthn.bin.coffee
Extensions: {}
[PASS] User presence must be the only flag set: 1 == 1
[PASS] Counter must be 4 bytes: 4 == 4

:: CBOR Attestation Object Data ::
RP ID Hash: a642d21b7c6d55e1ce23c5399828d2c749bf6a6ef2fe03cc9e10cdf4ed53088b
Counter: 00000005 Flags: 1

[PASS] Calculated RP ID hash must match what the browser derived.: pkLSG3xtVeHOI8U5mCjSx0m_am7y_gPMnhDN9O1TCIs == pkLSG3xtVeHOI8U5mCjSx0m_am7y_gPMnhDN9O1TCIs
ClientData buffer: 7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a227356393964616b54316b326b392d6146574e4a426b41222c226f726967696e223a2268747470733a2f2f776562617574686e2e62696e2e636f66666565222c2263726f73734f726967696e223a66616c73657d

ClientDataHash: 584f33bbac136d08e3058b2f131a3b4a2deb70705b9638142aa92ddb81cafb9f

Signed Data assembled: 166,66,210,27,124,109,85,225,206,35,197,57,152,40,210,199,73,191,106,110,242,254,3,204,158,16,205,244,237,83,8,139,1,0,0,0,5,88,79,51,187,172,19,109,8,227,5,139,47,19,26,59,74,45,235,112,112,91,150,56,20,42,169,45,219,129,202,251,159
[PASS] The token signature must be valid.


Raw request:
{
  "challenge": {
    "0": 177,
    "1": 95,
    "2": 125,
    "3": 117,
    "4": 169,
    "5": 19,
    "6": 214,
    "7": 77,
    "8": 164,
    "9": 247,
    "10": 230,
    "11": 133,
    "12": 88,
    "13": 210,
    "14": 65,
    "15": 144
  },
  "timeout": 60000,
  "allowCredentials": [
    {
      "type": "public-key",
      "id": {
        "0": 220,
        "1": 166,
        "2": 37,
        "3": 40,
        "4": 190,
        "5": 94,
        "6": 50,
        "7": 74,
        "8": 119,
        "9": 198,
        "10": 113,
        "11": 6,
        "12": 18,
        "13": 113,
        "14": 115,
        "15": 233,
        "16": 103,
        "17": 123,
        "18": 77,
        "19": 202,
        "20": 30,
        "21": 68,
        "22": 126,
        "23": 5,
        "24": 53,
        "25": 81,
        "26": 128,
        "27": 235,
        "28": 91,
        "29": 233,
        "30": 34,
        "31": 90,
        "32": 51,
        "33": 216,
        "34": 105,
        "35": 169,
        "36": 21,
        "37": 113,
        "38": 13,
        "39": 99,
        "40": 115,
        "41": 166,
        "42": 150,
        "43": 61,
        "44": 76,
        "45": 181,
        "46": 51,
        "47": 179,
        "48": 52,
        "49": 71,
        "50": 135,
        "51": 215,
        "52": 34,
        "53": 172,
        "54": 137,
        "55": 60,
        "56": 90,
        "57": 196,
        "58": 141,
        "59": 212,
        "60": 28,
        "61": 98,
        "62": 69,
        "63": 224
      },
      "transports": [
        "usb",
        "nfc",
        "ble"
      ]
    }
  ],
  "userVerification": "preferred",
  "extensions": {
    "txAuthSimple": "Execute order 66."
  }
}

Failures: 0 TODOs: 0
```
