import dataclasses, sys, unittest
sys.path.insert(0, '/workspace/shared/workos-independent-review-20261007/initial/tests')
from test_production_workos import *
from integration.workos import IssuerPinnedJWKS, JWKSConfig, CachedBearerVerifier

class ReviewAdversarial(WorkOSFixtures):
    def test_jwks_outage_after_refresh_is_not_terminal(self):
        cache = IssuerPinnedJWKS(JWKSConfig(ISSUER, CLIENT, 'session', API_ORIGIN+'/sso/jwks/'+CLIENT, ttl_seconds=10), transport=self.transport([(200,{'keys':[self.jwk]}),(503,{})]), clock=self.clock)
        verifier=CachedBearerVerifier(self.config,cache,clock=self.clock)
        client=WorkOSPublicClient(self.tc,verifier,VERIFY, transport=self.transport([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(refresh_token='fixture-rotated'))]),clock=self.clock,monotonic=self.clock)
        old=self.login(client); self.clock.advance(11)
        with self.assertRaises(WorkOSTransient):
            client.refresh(old.refresh_token)
        self.assertEqual(client.session_for(old.refresh_token).subject,SUBJECT)

    def test_unexpected_rejection_indistinguishable_from_invalid_grant(self):
        failures=[(400,{'error':'invalid_grant'}),(403,{'error':'network_policy_denied'}),(200,{'unexpected':'no tokens'})]
        observed=[]
        for response in failures:
            client=self.client([(200,self.start_body()),(200,self.token_body()),response])
            old=self.login(client)
            try: client.refresh(old.refresh_token)
            except Exception as exc: observed.append((type(exc).__name__,str(exc)))
        self.assertEqual(len(set(observed)),1)
        print('REPRO: invalid_grant, HTTP 403 policy denial, malformed HTTP 200 are identical public refresh results')

if __name__=='__main__': unittest.main(verbosity=2)
