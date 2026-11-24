CREATE TABLE control_customers (
 id uuid PRIMARY KEY, name varchar(180) NOT NULL, contact_email varchar(255) NOT NULL,
 status varchar(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','active','suspended')),
 notes text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE control_users (
 id uuid PRIMARY KEY, username varchar(180) NOT NULL UNIQUE, display_name varchar(180) NOT NULL,
 password_hash text NOT NULL, role varchar(30) NOT NULL CHECK(role IN ('platform_owner','platform_staff','approver','customer_owner')),
 customer_id uuid REFERENCES control_customers(id), enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(),
 CHECK((role='customer_owner' AND customer_id IS NOT NULL) OR (role<>'customer_owner' AND customer_id IS NULL))
);
CREATE TABLE control_sessions (
 token_hash char(64) PRIMARY KEY, user_id uuid NOT NULL REFERENCES control_users(id),
 expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX control_sessions_expiry ON control_sessions(expires_at);
CREATE TABLE control_applications (
 code varchar(80) PRIMARY KEY, name varchar(180) NOT NULL, description text NOT NULL DEFAULT '',
 icon varchar(80) NOT NULL DEFAULT 'bi-grid', landing_route varchar(255) NOT NULL,
 navigation jsonb NOT NULL DEFAULT '[]', enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE control_permissions (
 code varchar(180) PRIMARY KEY, application_code varchar(80) NOT NULL REFERENCES control_applications(code),
 description text NOT NULL DEFAULT '', enabled boolean NOT NULL DEFAULT true
);
CREATE TABLE control_plans (
 id uuid PRIMARY KEY, name varchar(180) NOT NULL, description text NOT NULL DEFAULT '',
 version integer NOT NULL DEFAULT 1, price_minor bigint NOT NULL CHECK(price_minor>=0),
 currency char(3) NOT NULL, duration_months integer NOT NULL CHECK(duration_months BETWEEN 1 AND 36),
 trial_days integer NOT NULL DEFAULT 0 CHECK(trial_days BETWEEN 0 AND 90),
 max_users integer NOT NULL CHECK(max_users BETWEEN 1 AND 100000),
 entitlements jsonb NOT NULL, published boolean NOT NULL DEFAULT false,
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE control_instances (
 id uuid PRIMARY KEY, customer_id uuid NOT NULL REFERENCES control_customers(id),
 name varchar(180) NOT NULL, api_origin varchar(500), key_hash char(64) NOT NULL,
 encrypted_key text NOT NULL, enabled boolean NOT NULL DEFAULT true,
 connected_at timestamptz, last_synced_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE control_requests (
 id uuid PRIMARY KEY, customer_id uuid NOT NULL REFERENCES control_customers(id),
 instance_id uuid NOT NULL REFERENCES control_instances(id), plan_id uuid NOT NULL REFERENCES control_plans(id),
 kind varchar(20) NOT NULL CHECK(kind IN ('purchase','trial')),
 status varchar(20) NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','cancelled')),
 plan_snapshot jsonb NOT NULL, requested_by uuid NOT NULL REFERENCES control_users(id),
 reviewed_by uuid REFERENCES control_users(id), review_note text, payment_reference varchar(255),
 created_at timestamptz NOT NULL DEFAULT now(), reviewed_at timestamptz
);
CREATE UNIQUE INDEX control_pending_request ON control_requests(instance_id) WHERE status='pending';
CREATE TABLE control_subscriptions (
 id uuid PRIMARY KEY, customer_id uuid NOT NULL REFERENCES control_customers(id),
 instance_id uuid NOT NULL REFERENCES control_instances(id), request_id uuid NOT NULL UNIQUE REFERENCES control_requests(id),
 kind varchar(20) NOT NULL CHECK(kind IN ('purchase','trial')),
 status varchar(20) NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','cancelled','superseded')),
 plan_snapshot jsonb NOT NULL, starts_at timestamptz NOT NULL, ends_at timestamptz NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), CHECK(ends_at>starts_at)
);
CREATE UNIQUE INDEX control_active_subscription ON control_subscriptions(instance_id) WHERE status='active';
CREATE INDEX control_subscriptions_customer ON control_subscriptions(customer_id,ends_at);
CREATE TABLE control_customer_roles (
 id uuid PRIMARY KEY, customer_id uuid NOT NULL REFERENCES control_customers(id), name varchar(100) NOT NULL,
 permission_codes jsonb NOT NULL, enabled boolean NOT NULL DEFAULT true,
 created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(customer_id,name)
);
CREATE TABLE control_audit (
 id bigserial PRIMARY KEY, actor_id uuid REFERENCES control_users(id), customer_id uuid REFERENCES control_customers(id),
 action varchar(120) NOT NULL, target_id varchar(180), details jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX control_audit_customer_page ON control_audit(customer_id,created_at,id);
