import { assert } from 'chai';
import { verifiable } from '@transmute/vc.js';
import revealDocument from './vcs/reveal-document.json';
import signedBbsVc from './vcs/signed-bbs-vc.json';
import { DefaultDocumentLoader, DocumentLoader } from '../src/index';
import { BbsBlsSignatureProof2020 } from '@transmute/bbs-bls12381-signature-2020';

describe('test bbs signature', function () {
    it('derive proof', async function () {
        const result = await verifiable.credential.derive({
            credential: signedBbsVc,
            frame: revealDocument,
            suite: new BbsBlsSignatureProof2020(),
            documentLoader: DocumentLoader.build([new DefaultDocumentLoader()]),
        });

        assert.exists(result);
        assert.exists(result.items[0]);

        const credentialSubject = Array.isArray(
            result.items[0].credentialSubject
        )
            ? result.items[0].credentialSubject[0]
            : result.items[0].credentialSubject;

        assert.exists(credentialSubject.field1);
    });
});
