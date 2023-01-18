import { assert } from 'chai';
import { ld as vcjs } from '@transmute/vc.js';
import vc from './vcs/vc.json';
import vcWithInvalidId from './vcs/vc-with-invalid-id.json';
import signedVc from './vcs/signed-vc.json';
import signedVcWithInvalidId from './vcs/signed-vc-with-invalid-id.json';
import { DefaultDocumentLoader, DocumentLoader } from '../src/index';
import { Ed25519Signature2018, Ed25519VerificationKey2018 } from '@transmute/ed25519-signature-2018';

describe('test vc', function () {
    it('create vc and verify VC with VALID id', async function () {
        const key = await Ed25519VerificationKey2018.from({
            "controller": "did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262",
            "id": "did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key",
            "publicKeyBase58": "DK4HTuz1Vm2M5erZz66QztfMwS1Vsz6V7gL1ss5eBZsq",
            "privateKeyBase58": "4me9Uirp8XuyETuDTXFm6yJVo6T5q6zFRtszWqJLJfwn2uZc5NgJoMCDgu7C3pHRVH5sF9WFFVTPD222sEiy2Rm5",
            "type": "Ed25519VerificationKey2018"
        })
        const result = await vcjs.createVerifiableCredential({
            credential: vc,
            suite: new Ed25519Signature2018({
                key
            }),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });
        assert.exists(result);

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: result,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()])
        });
        assert.isTrue(verifyVC.verified);
    });

    it('create vc and verify VC with INVALID id', async function () {
        const key = await Ed25519VerificationKey2018.from({
            "controller": "did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262",
            "id": "did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key",
            "publicKeyBase58": "DK4HTuz1Vm2M5erZz66QztfMwS1Vsz6V7gL1ss5eBZsq",
            "privateKeyBase58": "4me9Uirp8XuyETuDTXFm6yJVo6T5q6zFRtszWqJLJfwn2uZc5NgJoMCDgu7C3pHRVH5sF9WFFVTPD222sEiy2Rm5",
            "type": "Ed25519VerificationKey2018"
        })
        const result = await vcjs.createVerifiableCredential({
            credential: vcWithInvalidId,
            suite: new Ed25519Signature2018({
                key
            }),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });
        assert.exists(result);

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: result,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()])
        });
        assert.isTrue(verifyVC.verified);
    });

    it('remove field and verify signed VC with VALID ID', async function () {
        const vcToModify: any = Object.assign({}, signedVc);
        delete vcToModify.credentialSubject[0].field0;

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: vcToModify,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()])
        });
        assert.isFalse(verifyVC.verified);
    });

    it('remove field and verify signed VC with INVALID ID', async function () {
        const vcToModify: any = Object.assign({}, signedVcWithInvalidId);
        delete vcToModify.credentialSubject[0].field0;

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: vcToModify,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()])
        });
        assert.isFalse(verifyVC.verified);
    });
});
