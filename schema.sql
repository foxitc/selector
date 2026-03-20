-- ================================================================
-- THE CLUB — Database Schema
-- Infrastructure for Test Player / The Selector
-- Cat & Wickets gastro pub group
-- ================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Updated_at trigger
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER AS $$ BEGIN NEW.updated_at = NOW(); RETURN NEW; END; $$ LANGUAGE plpgsql;

-- ----------------------------------------------------------------
-- VENUES (pubs)
-- ----------------------------------------------------------------
CREATE TABLE venues (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name         VARCHAR(150) NOT NULL,
    short_name   VARCHAR(20)  NOT NULL,
    slug         VARCHAR(100) NOT NULL UNIQUE,
    address      TEXT,
    city         VARCHAR(100),
    is_active    BOOLEAN      NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trg_venues_updated_at BEFORE UPDATE ON venues FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ----------------------------------------------------------------
-- TEAM MEMBERS
-- ----------------------------------------------------------------
CREATE TABLE team_members (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    venue_id        UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    first_name      VARCHAR(100) NOT NULL,
    last_name       VARCHAR(100) NOT NULL,
    display_name    VARCHAR(200) NOT NULL,
    role            VARCHAR(100),
    department      VARCHAR(50) CHECK (department IN ('Kitchen','FOH','Bar','Management')),
    avatar_initials VARCHAR(3)   NOT NULL,
    avatar_color    VARCHAR(7)   NOT NULL DEFAULT '#fd6f53',
    -- External system IDs for connector matching
    epos_id         VARCHAR(100),  -- POSLink staff ID
    rota_id         VARCHAR(100),  -- RotaReady staff ID
    trail_id        VARCHAR(100),  -- Trail staff ID
    -- Programme status assigned by The Selector
    selector_tier       VARCHAR(20) CHECK (selector_tier IN ('could-say','should-say','have-to','review')) DEFAULT 'have-to',
    selector_status     VARCHAR(20) CHECK (selector_status IN ('on-programme','under-review','not-yet')) DEFAULT 'not-yet',
    selector_score      NUMERIC(6,2),
    selector_updated_at TIMESTAMPTZ,
    is_active       BOOLEAN      NOT NULL DEFAULT true,
    joined_at       DATE,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_team_members_venue ON team_members(venue_id);
CREATE INDEX idx_team_members_epos  ON team_members(epos_id) WHERE epos_id IS NOT NULL;
CREATE INDEX idx_team_members_rota  ON team_members(rota_id) WHERE rota_id IS NOT NULL;
CREATE TRIGGER trg_team_members_updated_at BEFORE UPDATE ON team_members FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ----------------------------------------------------------------
-- MANAGER ASSESSMENT (40% of The Selector score)
-- Completed weekly by the general manager per team member
-- ----------------------------------------------------------------
CREATE TABLE manager_assessments (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_member_id  UUID NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    venue_id        UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    assessor_id     UUID NOT NULL REFERENCES platform_users(id) ON DELETE SET NULL DEFERRABLE INITIALLY DEFERRED,
    week_ending     DATE NOT NULL,

    -- Six scored dimensions (1-5)
    product_confidence  SMALLINT NOT NULL CHECK (product_confidence BETWEEN 1 AND 5),
    guest_warmth        SMALLINT NOT NULL CHECK (guest_warmth BETWEEN 1 AND 5),
    table_reading       SMALLINT NOT NULL CHECK (table_reading BETWEEN 1 AND 5),
    values_alignment    SMALLINT NOT NULL CHECK (values_alignment BETWEEN 1 AND 5),

    -- Which coaching tier describes this team member this week
    coaching_tier   VARCHAR(20) NOT NULL CHECK (coaching_tier IN ('could-say','should-say','have-to')),

    -- Free text for AI coaching generation
    coaching_note   TEXT,

    -- Don't Say flags (comma-separated phrases manager noted)
    dont_say_flags  TEXT[],

    -- Computed weighted score (0-100) from the five dimensions
    assessment_score NUMERIC(5,2),

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (team_member_id, week_ending)
);
CREATE INDEX idx_assessments_member  ON manager_assessments(team_member_id);
CREATE INDEX idx_assessments_week    ON manager_assessments(week_ending);
CREATE INDEX idx_assessments_venue   ON manager_assessments(venue_id);
CREATE TRIGGER trg_assessments_updated_at BEFORE UPDATE ON manager_assessments FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ----------------------------------------------------------------
-- EPOS METRIC VALUES (40% of The Selector score)
-- Populated by connector from POSLink/EPOS system
-- ----------------------------------------------------------------
CREATE TABLE epos_metrics (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_member_id  UUID NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    venue_id        UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    week_ending     DATE NOT NULL,

    -- Attachment rates (0.0-1.0 — proportion of covers where this happened)
    food_attachment_rate    NUMERIC(5,4),  -- drink ordered with food
    dessert_conversion_rate NUMERIC(5,4),  -- dessert ordered at tables served
    coffee_conversion_rate  NUMERIC(5,4),  -- coffee ordered after mains
    wine_attachment_rate    NUMERIC(5,4),  -- wine recommended and taken

    -- Cover value vs shift average (1.0 = at average, 1.2 = 20% above)
    cover_value_index       NUMERIC(5,3),

    -- Total covers served this week
    covers_served           INTEGER,

    -- Raw data reference
    raw_data                JSONB DEFAULT '{}',
    source                  VARCHAR(50) DEFAULT 'api',
    synced_at               TIMESTAMPTZ,

    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_member_id, week_ending)
);
CREATE INDEX idx_epos_member ON epos_metrics(team_member_id);
CREATE INDEX idx_epos_week   ON epos_metrics(week_ending);

-- ----------------------------------------------------------------
-- OPERATIONAL METRICS (20% of The Selector score)
-- Populated by connectors from RotaReady and Trail
-- ----------------------------------------------------------------
CREATE TABLE operational_metrics (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_member_id  UUID NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    venue_id        UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    week_ending     DATE NOT NULL,

    -- RotaReady
    rota_adherence_pct   NUMERIC(5,2),   -- % of shifts attended on time
    shifts_completed     INTEGER,
    shifts_scheduled     INTEGER,
    late_arrivals        INTEGER DEFAULT 0,

    -- Trail
    trail_score          NUMERIC(5,2),   -- compliance score 0-100
    trail_checks_due     INTEGER,
    trail_checks_done    INTEGER,

    raw_data             JSONB DEFAULT '{}',
    synced_at            TIMESTAMPTZ,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_member_id, week_ending)
);
CREATE INDEX idx_ops_member ON operational_metrics(team_member_id);
CREATE INDEX idx_ops_week   ON operational_metrics(week_ending);

-- ----------------------------------------------------------------
-- THE SELECTOR — WEEKLY SCORES
-- Computed by The Selector engine, displayed in Test Player
-- ----------------------------------------------------------------
CREATE TABLE selector_scores (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    team_member_id  UUID NOT NULL REFERENCES team_members(id) ON DELETE CASCADE,
    venue_id        UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    week_ending     DATE NOT NULL,

    -- Composite score (0-100)
    total_score         NUMERIC(5,2) NOT NULL,
    previous_score      NUMERIC(5,2),
    score_change        NUMERIC(5,2),

    -- Component scores
    assessment_score    NUMERIC(5,2),   -- 40%
    epos_score          NUMERIC(5,2),   -- 40%
    operational_score   NUMERIC(5,2),   -- 20%

    -- Tier and status assigned by The Selector
    tier            VARCHAR(20) NOT NULL CHECK (tier IN ('could-say','should-say','have-to','review')),
    programme_status VARCHAR(20) NOT NULL CHECK (programme_status IN ('on-programme','under-review','not-yet')),

    -- Rank within venue
    rank_in_venue   INTEGER,

    -- Breakdown for transparency
    score_breakdown JSONB DEFAULT '{}',

    -- AI coaching narrative generated for this week
    coaching_narrative TEXT,
    narrative_generated_at TIMESTAMPTZ,

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (team_member_id, week_ending)
);
CREATE INDEX idx_selector_member ON selector_scores(team_member_id);
CREATE INDEX idx_selector_week   ON selector_scores(week_ending);
CREATE INDEX idx_selector_venue  ON selector_scores(venue_id);

-- ----------------------------------------------------------------
-- VENUE SCORES — aggregate for league table
-- ----------------------------------------------------------------
CREATE TABLE venue_scores (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    venue_id        UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    week_ending     DATE NOT NULL,
    total_score     NUMERIC(5,2) NOT NULL,
    previous_score  NUMERIC(5,2),
    score_change    NUMERIC(5,2),
    members_scored  INTEGER DEFAULT 0,
    league_position INTEGER,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (venue_id, week_ending)
);
CREATE INDEX idx_venue_scores_week ON venue_scores(week_ending);

-- ----------------------------------------------------------------
-- CONNECTORS — API integrations (encrypted credentials)
-- ----------------------------------------------------------------
CREATE TABLE connectors (
    id                    UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name                  VARCHAR(100) NOT NULL,
    provider              VARCHAR(50)  NOT NULL,  -- 'rotaready' | 'trail' | 'poslink' | 'custom'
    base_url              TEXT         NOT NULL,
    auth_type             VARCHAR(20)  NOT NULL,  -- 'api_key' | 'bearer' | 'basic'
    auth_config           JSONB        NOT NULL DEFAULT '{}',
    credentials_encrypted TEXT,                   -- AES-256-GCM
    is_active             BOOLEAN      NOT NULL DEFAULT true,
    last_sync_at          TIMESTAMPTZ,
    last_sync_status      VARCHAR(20),
    last_sync_message     TEXT,
    created_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at            TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trg_connectors_updated_at BEFORE UPDATE ON connectors FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ----------------------------------------------------------------
-- SYNC LOG — every connector run recorded
-- ----------------------------------------------------------------
CREATE TABLE sync_log (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    connector_id    UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    venue_id        UUID REFERENCES venues(id) ON DELETE SET NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'running',
    started_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    records_fetched INTEGER DEFAULT 0,
    records_stored  INTEGER DEFAULT 0,
    error_message   TEXT,
    raw_summary     JSONB DEFAULT '{}'
);
CREATE INDEX idx_sync_log_connector ON sync_log(connector_id);
CREATE INDEX idx_sync_log_started   ON sync_log(started_at DESC);

-- ----------------------------------------------------------------
-- DISPLAY TOKENS — TV screen authentication
-- ----------------------------------------------------------------
CREATE TABLE display_tokens (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    venue_id     UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    token        TEXT NOT NULL UNIQUE,
    display_type VARCHAR(20) NOT NULL DEFAULT 'team',
    -- Theme stored per display
    theme_config JSONB NOT NULL DEFAULT '{}',
    is_active    BOOLEAN NOT NULL DEFAULT true,
    last_accessed TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ----------------------------------------------------------------
-- PLATFORM USERS — coaches (general managers) and admins
-- ----------------------------------------------------------------
CREATE TABLE platform_users (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email        VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    first_name   VARCHAR(100),
    last_name    VARCHAR(100),
    role         VARCHAR(20)  NOT NULL DEFAULT 'coach' CHECK (role IN ('admin','coach','viewer')),
    venue_id     UUID REFERENCES venues(id) ON DELETE SET NULL,
    is_active    BOOLEAN      NOT NULL DEFAULT true,
    last_login   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
CREATE TRIGGER trg_users_updated_at BEFORE UPDATE ON platform_users FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ----------------------------------------------------------------
-- THE COACH'S FOCUS MESSAGE — shown on TV display
-- ----------------------------------------------------------------
CREATE TABLE focus_messages (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    venue_id    UUID NOT NULL REFERENCES venues(id) ON DELETE CASCADE,
    message     TEXT NOT NULL,
    set_by_id   UUID REFERENCES platform_users(id) ON DELETE SET NULL,
    week_ending DATE NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (venue_id, week_ending)
);

-- ----------------------------------------------------------------
-- AUDIT LOG
-- ----------------------------------------------------------------
CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID REFERENCES platform_users(id) ON DELETE SET NULL,
    action      VARCHAR(200) NOT NULL,
    entity_type VARCHAR(100),
    entity_id   UUID,
    ip_address  INET,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);
