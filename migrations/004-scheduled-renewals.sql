ALTER TABLE control_requests ADD COLUMN renewal_mode varchar(20) NOT NULL DEFAULT 'immediate' CHECK(renewal_mode IN ('immediate','after_current_term'));
ALTER TABLE control_subscriptions DROP CONSTRAINT control_subscriptions_status_check;
ALTER TABLE control_subscriptions ADD CONSTRAINT control_subscriptions_status_check CHECK(status IN ('active','suspended','cancelled','superseded','scheduled'));
CREATE UNIQUE INDEX control_scheduled_subscription ON control_subscriptions(instance_id) WHERE status='scheduled';
