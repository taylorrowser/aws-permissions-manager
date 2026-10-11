AWS Permissions Manager Handoff Package
Status checked 10 October 2026

START HERE
Read AWS_Permissions_Manager_Handoff.pdf, or edit the DOCX of the same name.
The ten-page guide covers requirements, architecture, current code, WorkOS
configuration, evidence, blockers, acceptance criteria and starting commands.
Its final section is a copy-paste continuation brief.

CONTENTS
sources/permission-broker-integrations-source-20261007.zip
  Full offline integration checkpoint. Extract and start with
  permission-broker-integrations/INTEGRATION-README.md.
  The integration/ package is the integration slice. The root simulator and
  root evidence directory are historical, not the latest integrated behavior.

sources/workos-auth-smoke-reviewed-source-20261007.zip
  Separate later authentication-only change set. Start with
  reviewed-auth-smoke/integration/WORKOS.md.
  Do not assume this has been merged and retested with the full broker.

owner-helper/aws-permissions-cli-owner-test.zip
  Standalone owner-run WorkOS diagnostic. Start with workos-owner-test/README.md.
  Its help and mocked tests are offline. --run starts a new live device flow
  and belongs only in the owner's private interactive terminal when ready.

evidence/permission-broker-integrations-evidence-20261007.zip
  Integration implementation report, source manifest and independent review.

evidence/workos-auth-smoke-review-evidence-20261007.zip
  Separate auth review, final acceptance and source fingerprint.

SHA256SUMS.txt
  Integrity checksums for the guide files and all five unchanged archives.

IMPORTANT STATUS
No live AWS deployment, IAM enforcement or end-to-end broker authentication
is qualified. The infrastructure scaffold deliberately fails deployment.
WorkOS CLI app configuration is verified; a hosted sign-in and reported device
approval do not establish a CLI exchange, refresh or session cleanup.

Archived integration evidence is 177 passing tests with zero skips plus
17 independent controls. The separate auth subset is 106 tests plus 9 controls.
The owner helper is 27 mocked tests repeated across five Node runtimes.
Fresh 10 October integration recovery verification passed 173 tests with
4 SDK tests skipped for missing boto3; the owner helper passed 27 tests.
These are separate checkpoints, not an additive production-security score.

No canonical broker Git repository, branch or commit is verified. Preserve
the source archives and manifests, establish a repository, then integrate and
retest deliberately. Project reference links may require the owner's access;
the included code and evidence do not depend on those links.

Do not put real tokens, device secrets, API keys or AWS credentials into chat,
logs or source files. Never invoke real credential_process output through an
assistant-visible command capture. New live access, deployment and IAM changes
require the applicable owner authorization and review described in the guide.
