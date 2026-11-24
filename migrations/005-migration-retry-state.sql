-- IAM's rollback marker is migrated separately in the IAM database.
CREATE INDEX control_action_tokens_expiry ON control_action_tokens(expires_at);
