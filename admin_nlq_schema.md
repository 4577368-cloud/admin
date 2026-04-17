# Admin NLQ Schema (auto-generated)

Updated at: 2026-04-16T01:44:51.329Z

Use this schema to answer admin natural-language questions by generating SELECT SQL only.

## Tables

- `auth.users`
  - `instance_id` uuid
  - `id` uuid
  - `aud` character varying
  - `role` character varying
  - `email` character varying
  - `encrypted_password` character varying
  - `email_confirmed_at` timestamp with time zone
  - `invited_at` timestamp with time zone
  - `confirmation_token` character varying
  - `confirmation_sent_at` timestamp with time zone
  - `recovery_token` character varying
  - `recovery_sent_at` timestamp with time zone
  - `email_change_token_new` character varying
  - `email_change` character varying
  - `email_change_sent_at` timestamp with time zone
  - `last_sign_in_at` timestamp with time zone
  - `raw_app_meta_data` jsonb
  - `raw_user_meta_data` jsonb
  - `is_super_admin` boolean
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `phone` text
  - `phone_confirmed_at` timestamp with time zone
  - `phone_change` text
  - `phone_change_token` character varying
  - `phone_change_sent_at` timestamp with time zone
  - `confirmed_at` timestamp with time zone
  - `email_change_token_current` character varying
  - `email_change_confirm_status` smallint
  - `banned_until` timestamp with time zone
  - `reauthentication_token` character varying
  - `reauthentication_sent_at` timestamp with time zone
  - `is_sso_user` boolean
  - `deleted_at` timestamp with time zone
  - `is_anonymous` boolean

- `public.user_stats`
  - `user_id` uuid
  - `free_quota_used` integer
  - `total_prompts` bigint
  - `is_vip` boolean
  - `vip_unlocked_at` timestamp with time zone
  - `updated_at` timestamp with time zone

- `public.user_prompt_logs`
  - `id` bigint
  - `user_id` uuid
  - `conversation_id` text
  - `content_preview` text
  - `extracted_urls` jsonb
  - `created_at` timestamp with time zone
  - `snapshot_sources` jsonb

- `public.share_links`
  - `id` uuid
  - `owner_user_id` uuid
  - `short_code` text
  - `created_at` timestamp with time zone
  - `owner_email` text
  - `owner_is_anonymous` boolean

- `public.share_link_visits`
  - `id` bigint
  - `share_link_id` uuid
  - `visitor_user_id` uuid
  - `created_at` timestamp with time zone
  - `visitor_email` text
  - `visitor_is_anonymous` boolean
  - `visitor_provider` text

- `public.share_link_oauth_attributions`
  - `id` bigint
  - `share_link_id` uuid
  - `short_code` text
  - `sharer_user_id` uuid
  - `sharer_email` text
  - `attributed_user_id` uuid
  - `visitor_email` text
  - `oauth_provider` text
  - `created_at` timestamp with time zone

- `public.ai_model_reply_logs`
  - `id` bigint
  - `user_id` uuid
  - `conversation_id` text
  - `model_id` text
  - `model_route` text
  - `has_image` boolean
  - `created_at` timestamp with time zone
  - `user_prompt_preview` text
  - `assistant_reply_preview` text

- `auth.audit_log_entries`
  - `instance_id` uuid
  - `id` uuid
  - `payload` json
  - `created_at` timestamp with time zone
  - `ip_address` character varying

- `auth.custom_oauth_providers`
  - `id` uuid
  - `provider_type` text
  - `identifier` text
  - `name` text
  - `client_id` text
  - `client_secret` text
  - `acceptable_client_ids` ARRAY
  - `scopes` ARRAY
  - `pkce_enabled` boolean
  - `attribute_mapping` jsonb
  - `authorization_params` jsonb
  - `enabled` boolean
  - `email_optional` boolean
  - `issuer` text
  - `discovery_url` text
  - `skip_nonce_check` boolean
  - `cached_discovery` jsonb
  - `discovery_cached_at` timestamp with time zone
  - `authorization_url` text
  - `token_url` text
  - `userinfo_url` text
  - `jwks_uri` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone

- `auth.flow_state`
  - `id` uuid
  - `user_id` uuid
  - `auth_code` text
  - `code_challenge_method` USER-DEFINED
  - `code_challenge` text
  - `provider_type` text
  - `provider_access_token` text
  - `provider_refresh_token` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `authentication_method` text
  - `auth_code_issued_at` timestamp with time zone
  - `invite_token` text
  - `referrer` text
  - `oauth_client_state_id` uuid
  - `linking_target_id` uuid
  - `email_optional` boolean

- `auth.identities`
  - `provider_id` text
  - `user_id` uuid
  - `identity_data` jsonb
  - `provider` text
  - `last_sign_in_at` timestamp with time zone
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `email` text
  - `id` uuid

- `auth.instances`
  - `id` uuid
  - `uuid` uuid
  - `raw_base_config` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone

- `auth.mfa_amr_claims`
  - `session_id` uuid
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `authentication_method` text
  - `id` uuid

- `auth.mfa_challenges`
  - `id` uuid
  - `factor_id` uuid
  - `created_at` timestamp with time zone
  - `verified_at` timestamp with time zone
  - `ip_address` inet
  - `otp_code` text
  - `web_authn_session_data` jsonb

- `auth.mfa_factors`
  - `id` uuid
  - `user_id` uuid
  - `friendly_name` text
  - `factor_type` USER-DEFINED
  - `status` USER-DEFINED
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `secret` text
  - `phone` text
  - `last_challenged_at` timestamp with time zone
  - `web_authn_credential` jsonb
  - `web_authn_aaguid` uuid
  - `last_webauthn_challenge_data` jsonb

- `auth.oauth_authorizations`
  - `id` uuid
  - `authorization_id` text
  - `client_id` uuid
  - `user_id` uuid
  - `redirect_uri` text
  - `scope` text
  - `state` text
  - `resource` text
  - `code_challenge` text
  - `code_challenge_method` USER-DEFINED
  - `response_type` USER-DEFINED
  - `status` USER-DEFINED
  - `authorization_code` text
  - `created_at` timestamp with time zone
  - `expires_at` timestamp with time zone
  - `approved_at` timestamp with time zone
  - `nonce` text

- `auth.oauth_client_states`
  - `id` uuid
  - `provider_type` text
  - `code_verifier` text
  - `created_at` timestamp with time zone

- `auth.oauth_clients`
  - `id` uuid
  - `client_secret_hash` text
  - `registration_type` USER-DEFINED
  - `redirect_uris` text
  - `grant_types` text
  - `client_name` text
  - `client_uri` text
  - `logo_uri` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `deleted_at` timestamp with time zone
  - `client_type` USER-DEFINED
  - `token_endpoint_auth_method` text

- `auth.oauth_consents`
  - `id` uuid
  - `user_id` uuid
  - `client_id` uuid
  - `scopes` text
  - `granted_at` timestamp with time zone
  - `revoked_at` timestamp with time zone

- `auth.one_time_tokens`
  - `id` uuid
  - `user_id` uuid
  - `token_type` USER-DEFINED
  - `token_hash` text
  - `relates_to` text
  - `created_at` timestamp without time zone
  - `updated_at` timestamp without time zone

- `auth.refresh_tokens`
  - `instance_id` uuid
  - `id` bigint
  - `token` character varying
  - `user_id` character varying
  - `revoked` boolean
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `parent` character varying
  - `session_id` uuid

- `auth.saml_providers`
  - `id` uuid
  - `sso_provider_id` uuid
  - `entity_id` text
  - `metadata_xml` text
  - `metadata_url` text
  - `attribute_mapping` jsonb
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `name_id_format` text

- `auth.saml_relay_states`
  - `id` uuid
  - `sso_provider_id` uuid
  - `request_id` text
  - `for_email` text
  - `redirect_to` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `flow_state_id` uuid

- `auth.schema_migrations`
  - `version` character varying

- `auth.sessions`
  - `id` uuid
  - `user_id` uuid
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `factor_id` uuid
  - `aal` USER-DEFINED
  - `not_after` timestamp with time zone
  - `refreshed_at` timestamp without time zone
  - `user_agent` text
  - `ip` inet
  - `tag` text
  - `oauth_client_id` uuid
  - `refresh_token_hmac_key` text
  - `refresh_token_counter` bigint
  - `scopes` text

- `auth.sso_domains`
  - `id` uuid
  - `sso_provider_id` uuid
  - `domain` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone

- `auth.sso_providers`
  - `id` uuid
  - `resource_id` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `disabled` boolean

- `auth.webauthn_challenges`
  - `id` uuid
  - `user_id` uuid
  - `challenge_type` text
  - `session_data` jsonb
  - `created_at` timestamp with time zone
  - `expires_at` timestamp with time zone

- `auth.webauthn_credentials`
  - `id` uuid
  - `user_id` uuid
  - `credential_id` bytea
  - `public_key` bytea
  - `attestation_type` text
  - `aaguid` uuid
  - `sign_count` bigint
  - `transports` jsonb
  - `backup_eligible` boolean
  - `backed_up` boolean
  - `friendly_name` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `last_used_at` timestamp with time zone

- `public.admin_accounts`
  - `id` bigint
  - `username` text
  - `password_hash` text
  - `is_active` boolean
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone

- `public.app_analytics_events`
  - `id` bigint
  - `user_id` uuid
  - `event_name` text
  - `properties` jsonb
  - `created_at` timestamp with time zone

- `public.app_config`
  - `key` text
  - `value` text

- `public.product_inquiries`
  - `id` uuid
  - `user_id` uuid
  - `user_email` text
  - `product_snapshot` jsonb
  - `whatsapp` text
  - `demand` text
  - `status` text
  - `created_at` timestamp with time zone
  - `updated_at` timestamp with time zone
  - `reply_content` text
  - `reply_at` timestamp with time zone
  - `replied_by` text
  - `reply_messages` jsonb
  - `reply_count` integer
  - `user_seen_reply_count` integer

- `public.tangbuy_click_events`
  - `id` bigint
  - `user_id` uuid
  - `event_kind` text
  - `target_url` text
  - `meta` jsonb
  - `created_at` timestamp with time zone

- `public.v_prompt_logs_cst`
  - `id` bigint
  - `user_id` uuid
  - `email` character varying
  - `is_anonymous` boolean
  - `conversation_id` text
  - `content_preview` text
  - `extracted_urls` jsonb
  - `created_at_cst` text

- `public.v_prompt_logs_with_user`
  - `id` bigint
  - `created_at` timestamp with time zone
  - `conversation_id` text
  - `content_preview` text
  - `extracted_urls` jsonb
  - `user_email` character varying
  - `is_anonymous` boolean

- `public.v_share_oauth_attributions_detail`
  - `short_code` text
  - `sharer` text
  - `attributed_email` text
  - `oauth_provider` text
  - `attributed_at_cst` text
  - `user_is_vip` boolean
  - `user_total_prompts` bigint

- `public.v_share_visits_detail`
  - `short_code` text
  - `sharer` text
  - `clicked_at_cst` text
  - `visitor_user_id` uuid
  - `visitor_email` text
  - `visitor_is_anonymous` boolean
  - `visitor_provider` text
  - `has_oauth_attribution` boolean

- `public.v_user_overview`
  - `user_id` uuid
  - `email` character varying
  - `auth_provider` text
  - `is_anonymous` boolean
  - `is_vip` boolean
  - `vip_unlocked_at_cst` text
  - `free_quota_used` integer
  - `total_prompts` bigint
  - `distinct_conversations` bigint
  - `first_prompt_cst` text
  - `last_prompt_cst` text
  - `tangbuy_clicks` bigint
  - `distinct_tangbuy_urls` bigint
  - `analytics_events` bigint
  - `share_short_code` text
  - `total_share_clicks` bigint
  - `unique_share_visitors` bigint
  - `oauth_attributed_users` bigint
  - `attributed_user_emails` text
  - `invited_by_share_code` text
  - `invited_by_email` text
  - `registered_at_cst` text
  - `last_sign_in_cst` text
  - `last_active_cst` text

## SQL Rules

1. SELECT/CTE only, no DML/DDL.
2. Relative dates (today/yesterday/last N days) use Asia/Shanghai (UTC+8).
3. For list/detail requests, avoid random single row; use aggregation or explicit ordering.
