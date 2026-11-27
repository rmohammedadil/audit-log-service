# Engineering Claim Evidence Mapping

This mapping links implementation claims to repository evidence. The Task 51
application validation was executed at
`3b0eb5d6601e3c74f938ad8afedabf4f99140c2b`; later documentation commits do
not change that tested application revision. Test names are evidence of the
automated assertions, not a claim of production or regulatory certification.

| Claim | Implementation reference | Automated evidence | Task 51 / limitations |
| --- | --- | --- | --- |
| Application-level append-only event persistence | `app/services/v4_audit_service.py::append_v4_audit_event`, `V4TenantChainState` | `test_tenant_chains_are_independent_and_checkpointed`, `test_append_and_checkpoint_are_rolled_back_together` | Live creation/replay passed. A privileged database administrator can still rewrite coordinated same-database evidence. |
| Deterministic content hashes and tenant chains | `canonicalize_v4_content`, `calculate_v4_content_hash`, `calculate_v4_chain_hash`, `v4_genesis_chain_hash` in `app/services/v4_audit_service.py` | `test_v4_hashing_is_deterministic_and_binds_tenant_reference_and_sequence` | Tenant-chain verification passed live; SQLite is not an external trust anchor. |
| Tamper detection and checkpoint verification | `verify_v4_tenant_chain`, `verify_v4_lifecycle` | `test_v4_verification_detects_tenant_chain_evidence_tampering`, `test_v4_verification_reports_malformed_persisted_evidence`, `test_v4_deleted_redaction_metadata_fails_closed_without_exposing_payload` | Live tenant verification passed for healthy evidence. Coordinated privileged rewrites remain a documented risk. |
| JWT authentication and tenant/resource authorization | `app/auth.py::authenticate_v4`, `require_v4_roles`; `app/authorization_service.py::require_resource_grant`, `require_tenant_grant` | `test_v4_authentication_rejects_missing_blank_or_malformed_tenant_claim`, `test_v4_authentication_rejects_invalid_signature_and_expiry`, `test_resource_grants_require_an_exact_active_match` | Missing, invalid, and legacy JWTs were rejected in live HTTP validation. |
| Cross-tenant and cross-resource isolation | Tenant filters in `app/api/v4_audit_routes.py::list_events`, `access_reports`, `export_events` | `test_default_application_prevents_cross_tenant_and_cross_resource_reads`, `test_v4_queries_authorize_before_pagination_and_actor_filtering`, `test_v4_actor_exports_use_authorized_subset_without_existence_oracle` | Live cross-tenant and cross-resource requests returned empty authorized subsets without disclosed evidence. |
| Revocation and inactive membership enforcement | `active_tenant_principal`, grant queries in `app/authorization_service.py` | `test_v4_denies_inactive_or_revoked_replay_and_allows_tenant_scoped_same_key`, `test_v4_inactive_memberships_deny_sensitive_operations`, `test_v4_revoked_lifecycle_permissions_leave_evidence_unchanged` | Revoked read access produced an empty authorized result in the live run. |
| Transactional idempotency and rollback | `find_v4_replay`, `v4_request_fingerprint`, create route transaction in `app/api/v4_audit_routes.py::create_event` | `test_v4_create_and_tenant_scoped_replay`, `test_v4_idempotency_fingerprint_conflict_preserves_the_original_event`, `test_v4_create_rolls_back_and_sanitizes_unexpected_append_errors` | Live requests returned 201 on creation, 200 on identical replay, and 409 on conflict. |
| Retention and redaction integrity | `archive_v4_events`, `redact_v4_event`, `verify_v4_lifecycle` | `test_v4_retention_is_tenant_scoped_and_hides_archived_events`, `test_v4_lifecycle_rollback_and_noop_behavior`, `test_v4_partial_archive_metadata_deletion_is_detected` | Live retention execution and redaction projection passed. Redaction masks views; it does not erase originals. |
| Independently verifiable exports and signatures | `app/services/v4_export_service.py::create_v4_export`, `app/verify_v4_export.py::verify_v4_bundle`, `app/export_signing.py` | `test_valid_unsigned_and_signed_v4_bundles`, `test_signature_failures_fail_closed`, `test_v4_cli_reports_malformed_evidence_without_a_traceback` | Signed export and trusted-key offline verification passed live. Redacted originals and source-selection completeness cannot be independently proven offline. |
| Regulatory access reporting | `app/api/v4_audit_routes.py::access_reports`; canonical contract in `app/schemas.py::AuditEventCreate` | `test_v4_verify_and_access_reports_are_tenant_resource_scoped`, `test_v4_archive_filtering_occurs_before_pagination` | Live reporting passed for recorded canonical access events only; it does not prove external access-log completeness. |
| Coverage thresholds and CI evidence | `scripts/check_coverage.py`; `.github/workflows/ci.yml` regression job | `tests/test_coverage_gate.py::test_valid_report_passes_all_thresholds`, `test_main_returns_documented_exit_codes` | Task 51 gate passed. CI is configured to capture evidence, but no Task 51 remote CI or Docker run is claimed. |

## Local Task 51 evidence

The following local, ignored artifacts are evidence paths on the validation
machine only. They are not committed and are not guaranteed to be available to
remote reviewers:

- `.coverage-reports/task51-manifest.txt`
- `.coverage-reports/task51-pytest.log` and `task51-pytest.exitcode`
- `.coverage-reports/coverage.json`, `coverage.xml`, `html/index.html`, and
  `junit.xml`
- `.coverage-reports/task51-coverage-gate.log` and
  `task51-coverage-gate.exitcode`
- `C:\Charles_Schwab\final-e2e-validation\task51-20261127T025402Z-241e8f3d-report.json`
