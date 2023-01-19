import { assert } from 'chai';
import { ld as vcjs } from '@transmute/vc.js';
import vc from './vcs/vc.json';
import vcWithInvalidId from './vcs/vc-with-invalid-id.json';
import signedVc from './vcs/signed-vc.json';
import signedVcWithInvalidId from './vcs/signed-vc-with-invalid-id.json';
import bbsVc from './vcs/bbs-vc.json';
import { DefaultDocumentLoader, DocumentLoader } from '../src/index';
import {
    Ed25519Signature2018,
    Ed25519VerificationKey2018,
} from '@transmute/ed25519-signature-2018';
import { Bls12381G2KeyPair } from '@transmute/bbs-bls12381-signature-2020';
import { BbsBlsSignature2020 } from '@transmute/bbs-bls12381-signature-2020';
import {
    BbsBlsSignature2020 as BbsBlsSignature2020MattrBlobal,
    Bls12381G2KeyPair as Bls12381G2KeyPairMattrGlobal,
} from '@mattrglobal/jsonld-signatures-bbs';

describe('test vc', function () {
    it('create vc and verify VC with VALID id', async function () {
        const key = await Ed25519VerificationKey2018.from({
            controller:
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262',
            id: 'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key',
            publicKeyBase58: 'DK4HTuz1Vm2M5erZz66QztfMwS1Vsz6V7gL1ss5eBZsq',
            privateKeyBase58:
                '4me9Uirp8XuyETuDTXFm6yJVo6T5q6zFRtszWqJLJfwn2uZc5NgJoMCDgu7C3pHRVH5sF9WFFVTPD222sEiy2Rm5',
            type: 'Ed25519VerificationKey2018',
        });
        const result = await vcjs.createVerifiableCredential({
            credential: vc,
            suite: new Ed25519Signature2018({
                key,
            }),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.exists(result);

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: result,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.isTrue(verifyVC.verified);
    });

    it('create vc and verify VC with INVALID id', async function () {
        const key = await Ed25519VerificationKey2018.from({
            controller:
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262',
            id: 'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key',
            publicKeyBase58: 'DK4HTuz1Vm2M5erZz66QztfMwS1Vsz6V7gL1ss5eBZsq',
            privateKeyBase58:
                '4me9Uirp8XuyETuDTXFm6yJVo6T5q6zFRtszWqJLJfwn2uZc5NgJoMCDgu7C3pHRVH5sF9WFFVTPD222sEiy2Rm5',
            type: 'Ed25519VerificationKey2018',
        });
        const result = await vcjs.createVerifiableCredential({
            credential: vcWithInvalidId,
            suite: new Ed25519Signature2018({
                key,
            }),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.exists(result);

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: result,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.isTrue(verifyVC.verified);
    });

    it('create vc with bbs signature and verify VC with VALID id', async function () {
        const key = await Bls12381G2KeyPair.from({
            controller:
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262',
            id: 'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key1',
            publicKeyBase58:
                '23M4HRjNucgT8g27D6zyEu5aH4qRvrgZQUmBzUs93zWK12GDhiJYJBTL9hpHSa2n6ckgSxJK4L8bn8yrE9pYyfvadCHYS5apYDmMt7DLaeygzWEXcZw7z7FCx3WbVruwXBK5',
            privateKeyBase58: '2TC8MYHkLWe9REgkn2kzxz12xRz5PiHXCK9ChygCzYvW',
            type: 'Bls12381G2Key2020',
        });
        const result = await vcjs.createVerifiableCredential({
            credential: Object.assign({}, bbsVc),
            suite: new BbsBlsSignature2020({
                key,
            }),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.exists(result);

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: result,
            suite: new BbsBlsSignature2020(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.isTrue(verifyVC.verified);
    });

    it('create vc with bbs signature and verify VC with VALID id with mattrglobal library', async function () {
        const key = await Bls12381G2KeyPairMattrGlobal.from({
            controller:
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262',
            id: 'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key1',
            publicKeyBase58:
                '23M4HRjNucgT8g27D6zyEu5aH4qRvrgZQUmBzUs93zWK12GDhiJYJBTL9hpHSa2n6ckgSxJK4L8bn8yrE9pYyfvadCHYS5apYDmMt7DLaeygzWEXcZw7z7FCx3WbVruwXBK5',
            privateKeyBase58: '2TC8MYHkLWe9REgkn2kzxz12xRz5PiHXCK9ChygCzYvW',
        });
        const result = await vcjs.createVerifiableCredential({
            credential: Object.assign({}, bbsVc),
            suite: new BbsBlsSignature2020MattrBlobal({
                key,
            }),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.exists(result);

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: result,
            suite: new BbsBlsSignature2020MattrBlobal(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.isTrue(verifyVC.verified);
    });

    it('remove field and verify signed VC with VALID ID', async function () {
        const vcToModify: any = Object.assign({}, signedVc);
        delete vcToModify.credentialSubject[0].field0;

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: vcToModify,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.isFalse(verifyVC.verified);
    });

    it('remove field and verify signed VC with INVALID ID', async function () {
        const vcToModify: any = Object.assign({}, signedVcWithInvalidId);
        delete vcToModify.credentialSubject[0].field0;

        const verifyVC = await vcjs.verifyVerifiableCredential({
            credential: vcToModify,
            suite: new Ed25519Signature2018(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.isFalse(verifyVC.verified);
    });
});
