import didContexts from '@transmute/did-context';
import credentialsContexts from '@transmute/credentials-context';
import securityContexts from '@transmute/security-context';
import { IDocumentFormat } from './document-format';
import { DocumentLoader } from './document-loader';
import schema from './contexts/schema.json';
import did from './did-documents/did.json';

/**
 * Default Documents Loader
 * Used for VC validation.
 */
export class DefaultDocumentLoader extends DocumentLoader {
    /**
     * Has context
     * @param iri
     */
    public async has(iri: string): Promise<boolean> {
        if ((didContexts.contexts as Map<string, object>).has(iri)) {
            return true;
        }
        if ((credentialsContexts.contexts as Map<string, object>).has(iri)) {
            return true;
        }
        if ((securityContexts.contexts as Map<string, object>).has(iri)) {
            return true;
        }
        if (iri === 'schema#c6f68dcd-d02d-4eb4-8787-66a57a4ce00f') {
            return true;
        }
        if (
            iri ===
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262' ||
            iri ===
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key'
        ) {
            return true;
        }
        return false;
    }

    /**
     * Get document
     * @param iri
     */
    public async get(iri: string): Promise<IDocumentFormat> {
        if ((didContexts.contexts as Map<string, object>).has(iri)) {
            return {
                documentUrl: iri,
                document: didContexts.contexts.get(iri),
            };
        }
        if ((credentialsContexts.contexts as Map<string, object>).has(iri)) {
            return {
                documentUrl: iri,
                document: credentialsContexts.contexts.get(iri),
            };
        }
        if ((securityContexts.contexts as Map<string, object>).has(iri)) {
            return {
                documentUrl: iri,
                document: securityContexts.contexts.get(iri),
            };
        }
        if (iri === 'schema#c6f68dcd-d02d-4eb4-8787-66a57a4ce00f') {
            return {
                documentUrl: iri,
                document: schema,
            };
        }
        if (
            iri ===
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262' ||
            iri ===
                'did:hedera:testnet:Gc5Vs4eQ8EvdPodjTz64AqoSX2JQcCsgvDntTgrsgZ1f_0.0.49251262#did-root-key'
        ) {
            return {
                documentUrl: iri,
                document: did,
            };
        }
        throw new Error('IRI not found: ' + iri);
    }
}
