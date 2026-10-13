"""Independent offline assertions, run from a reviewed snapshot via PYTHONPATH."""
import collections, dataclasses, json, sys, unittest
from test_production_workos import (WorkOSFixtures, ISSUER, CLIENT, SUBJECT, VERIFY,
    REFRESH, DEVICE, NOW, API_ORIGIN, AUTHENTICATE, DEVICE_AUTHORIZE)
from integration.auth import AuthError
from integration.auth_smoke import MemorySmoke,SmokeConfig
from integration.workos import (IssuerPinnedJWKS,JWKSConfig,CachedBearerVerifier,
    WorkOSPublicClient,WorkOSTransient,WorkOSReconnectRequired,WorkOSInvalidGrant)

class IndependentChecks(WorkOSFixtures):
    def cached_client(self, token_responses, jwks_responses):
        cache=IssuerPinnedJWKS(JWKSConfig(ISSUER,CLIENT,'session',API_ORIGIN+'/sso/jwks/'+CLIENT,ttl_seconds=10),transport=self.transport(jwks_responses),clock=self.clock)
        verifier=CachedBearerVerifier(self.config,cache,clock=self.clock)
        return WorkOSPublicClient(self.tc,verifier,VERIFY,transport=self.transport(token_responses),clock=self.clock,monotonic=self.clock)
    def token_requests(self):
        return sum(str(req.url)==AUTHENTICATE for req in self.requests)
    def test_rotated_candidate_survives_jwks_outage_without_second_refresh(self):
        c=self.cached_client([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(refresh_token='review-rotated-fixture'))],[(200,{'keys':[self.jwk]}),(503,{}),(200,{'keys':[self.jwk]})])
        old=self.login(c);self.clock.advance(11)
        with self.assertRaises(WorkOSTransient):c.refresh(old.refresh_token)
        self.assertEqual(c.session_for(old.refresh_token).subject,SUBJECT)
        count=self.token_requests();self.clock.advance(5)
        new=c.refresh(old.refresh_token)
        self.assertEqual(new.refresh_token,'review-rotated-fixture')
        self.assertEqual(self.token_requests(),count,'unverified rotated response should be reverified without spending another refresh')
        self.assertEqual(new.identity_binding,old.identity_binding)
    def test_rotated_new_kid_waits_through_recent_successful_cache_cooldown(self):
        c=self.cached_client([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(access_token=self.token(key=self.other_key,kid='offline-key-2'),refresh_token='review-k2-rotated'))],[(200,{'keys':[self.jwk]}),(200,{'keys':[self.jwk2]})])
        old=self.login(c)
        with self.assertRaises(WorkOSTransient):c.refresh(old.refresh_token)
        count=self.token_requests();self.clock.advance(5)
        rotated=c.refresh(old.refresh_token)
        self.assertEqual(rotated.refresh_token,'review-k2-rotated')
        self.assertEqual(rotated.identity_binding,old.identity_binding)
        self.assertEqual(self.token_requests(),count)
    def test_device_response_survives_jwks_outage_without_repolling_consumed_code(self):
        c=self.cached_client([(200,self.start_body()),(200,self.token_body())],[(503,{}),(200,{'keys':[self.jwk]})])
        challenge=c.start();self.clock.advance(5)
        with self.assertRaises(WorkOSTransient):c.poll(challenge.device_code)
        count=self.token_requests();self.clock.advance(5)
        accepted=c.poll(challenge.device_code)
        self.assertEqual(accepted.identity_binding['subject'],SUBJECT)
        self.assertEqual(self.token_requests(),count)
    def test_exact_invalid_grant_distinguished_from_policy_or_parse_failure(self):
        cases=[(400,{'error':'invalid_grant'},True),(403,{'error':'invalid_grant'},False),(400,{'error':'invalid_request'},False),(200,{'unexpected':'REVIEW_SECRET_SENTINEL'},False)]
        for status,body,proof in cases:
            c=self.client([(200,self.start_body()),(200,self.token_body()),(status,body)])
            old=self.login(c);count=self.token_requests()
            with self.assertRaises(WorkOSReconnectRequired) as cm:c.refresh(old.refresh_token)
            self.assertEqual(isinstance(cm.exception,WorkOSInvalidGrant),proof)
            self.assertEqual(self.token_requests(),count+1)
            self.assertNotIn('REVIEW_SECRET_SENTINEL',str(cm.exception))
    def test_identity_rejection_never_becomes_provider_invalid_grant(self):
        c=self.client([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(access_token=self.token(sid='review-wrong-session')))])
        old=self.login(c)
        with self.assertRaises(WorkOSReconnectRequired) as cm:c.refresh(old.refresh_token)
        self.assertNotIsInstance(cm.exception,WorkOSInvalidGrant)
    def test_unknown_key_refresh_retains_fresh_good_key_then_stops_at_ttl(self):
        cache=IssuerPinnedJWKS(JWKSConfig(ISSUER,CLIENT,'session',API_ORIGIN+'/sso/jwks/'+CLIENT,ttl_seconds=10),transport=self.transport([(200,{'keys':[self.jwk]}),(503,{}),(503,{})]),clock=self.clock)
        v=CachedBearerVerifier(self.config,cache,clock=self.clock);valid=self.token()
        v.verify(valid);self.clock.advance(5)
        with self.assertRaises(WorkOSTransient):v.verify(self.token(key=self.other_key,kid='offline-key-2'))
        self.assertEqual(v.verify(valid).subject,SUBJECT)
        self.clock.advance(5)
        with self.assertRaises(AuthError):v.verify(valid)
    def harness(self,responses):
        cfg=SmokeConfig(ISSUER,CLIENT,'offline-owner',SUBJECT,VERIFY,API_ORIGIN+'/sso/jwks/'+CLIENT,int(self.clock())+3600)
        return MemorySmoke(self.client(responses),self.verifier,cfg,clock=self.clock,monotonic=self.clock)
    def fail_second_verification_once(self):
        original=self.verifier.verify_details;count=[0]
        def flaky(token):
            count[0]+=1
            if count[0]==2:raise WorkOSTransient()
            return original(token)
        self.verifier.verify_details=flaky
    def test_harness_retains_provider_accepted_rotated_pair_during_second_verification_outage(self):
        smoke=self.harness([(200,self.start_body()),(200,self.token_body()),(200,self.token_body(refresh_token='review-harness-rotated'))])
        smoke.start();self.clock.advance(5);smoke.poll();self.fail_second_verification_once()
        status=smoke.refresh();self.assertEqual(status['phase'],'provider_transient')
        count=self.token_requests();self.clock.advance(5)
        recovered=smoke.refresh()
        self.assertTrue(recovered['refresh_verified'])
        self.assertEqual(smoke._tokens.refresh_token,'review-harness-rotated')
        self.assertEqual(self.token_requests(),count,'harness must reverify its private candidate, never spend another refresh')
    def test_harness_retains_device_pair_during_second_verification_outage(self):
        smoke=self.harness([(200,self.start_body()),(200,self.token_body())]);self.fail_second_verification_once()
        smoke.start();self.clock.advance(5)
        status=smoke.poll();self.assertEqual(status['phase'],'provider_transient')
        count=self.token_requests();self.clock.advance(5)
        recovered=smoke.poll();self.assertTrue(recovered['authenticated'])
        self.assertEqual(self.token_requests(),count,'harness must not repoll consumed device grant')
    def test_clear_memory_prevents_local_refresh_or_revocation_claim(self):
        c=self.client([(200,self.start_body()),(200,self.token_body())]);old=self.login(c)
        c.clear_memory();count=len(self.requests)
        with self.assertRaises(WorkOSReconnectRequired) as cm:c.refresh(old.refresh_token)
        self.assertNotIsInstance(cm.exception,WorkOSInvalidGrant)
        self.assertEqual(len(self.requests),count)

if __name__=='__main__':unittest.main(verbosity=2)
