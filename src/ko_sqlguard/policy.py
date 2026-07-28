"""GuardPolicy: the single Pydantic model that configures every deterministic check.

Tier-2 seams (`pii_columns`, `cost_threshold`) are exposed here for API stability but
are NOT enforced in v1 — see cost.py / semantic.py.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .result import Severity

__all__ = [
    "GuardPolicy",
    "DEFAULT_BLOCKED_FUNCTIONS",
    "BLOCKED_FUNCTION_PREFIXES",
    "ALLOWED_PG_FUNCTIONS",
    "SYSTEM_CATALOG_SCHEMAS",
    "DEFAULT_BLOCKED_CATALOG_TABLES",
    "SYSTEM_CATALOG_NAME_PREFIXES",
    "DEFAULT_SENSITIVE_COLUMNS",
]

# Functions an LLM has no business calling in an analytics/read context. Matched on
# the AST function name (case-insensitive), never on the raw SQL string. This is a
# best-effort denylist of well-known dangerous built-ins: a denylist is inherently
# incomplete, so it is your SECOND line of defense behind a least-privilege DB role
# (a non-superuser cannot call most of these anyway). Extend via
# GuardPolicy.blocked_functions. Note: resource-exhaustion via ordinary functions
# (generate_series/repeat with huge args) is intentionally NOT covered here - bound
# that with the database's statement_timeout / work_mem, not a parser.
DEFAULT_BLOCKED_FUNCTIONS: frozenset[str] = frozenset(
    {
        # --- time-delay / DoS payloads ---
        "pg_sleep",
        "pg_sleep_for",
        "pg_sleep_until",
        # Cross-dialect time-based blind-SQLi delay primitives. PostgreSQL has no
        # sleep()/benchmark()/waitfor, but real-world injection payloads (and the
        # external SQLi corpora) carry the MySQL/MSSQL spellings verbatim; they
        # parse cleanly here as ordinary function calls, so block them by name as
        # the dialect-agnostic counterpart to pg_sleep. No benign analytics read
        # calls these (verified zero FP on the external benign set).
        "sleep",        # MySQL time-based blind: AND sleep(5)=0
        "benchmark",    # MySQL CPU-burn blind: AND benchmark(1e6, md5(now()))
        "waitfor",      # MSSQL time-based blind: WAITFOR DELAY '0:0:5'
        # --- filesystem access ---
        "pg_read_file",
        "pg_read_binary_file",
        "pg_ls_dir",
        "pg_ls_logdir",
        "pg_ls_waldir",
        "pg_ls_tmpdir",
        "pg_ls_archive_statusdir",
        "pg_logdir_ls",
        "pg_stat_file",
        "pg_file_write",
        "pg_file_unlink",
        "pg_file_rename",
        "pg_current_logfile",
        "pg_relation_filepath",
        "adminpack",
        # --- large objects (read/write server files & DB bytes) ---
        "lo_import",
        "lo_export",
        "lo_open",
        "lo_get",
        "lo_put",
        "lo_creat",
        "lo_create",
        "lo_unlink",
        "lo_from_bytea",
        "lo_truncate",
        "loread",
        "lowrite",
        # --- cross-server / network ---
        "dblink",
        "dblink_exec",
        "dblink_connect",
        "dblink_connect_u",
        "dblink_open",
        "dblink_fetch",
        "dblink_send_query",
        "dblink_get_result",
        "inet_server_addr",
        "inet_server_port",
        # Cross-dialect filesystem / cross-server primitives. PostgreSQL is the target,
        # but real-world SQLi payloads (and the external corpora) carry the MySQL/MSSQL
        # spellings verbatim and they parse here as ordinary function calls — block them
        # by name as the dialect-agnostic counterpart to pg_read_file / dblink. No benign
        # analytics read calls these.
        "load_file",          # MySQL: read a server file  (counterpart to pg_read_file)
        "openquery",          # MSSQL: run a query on a linked server (counterpart to dblink)
        "opendatasource",     # MSSQL: ad-hoc connect to an external data source
        "openrowset",         # MSSQL: ad-hoc remote/file rowset (also reads files)
        # --- admin / replication / backup / process control ---
        "pg_terminate_backend",
        "pg_cancel_backend",
        "pg_reload_conf",
        "pg_rotate_logfile",
        "pg_promote",
        "pg_switch_wal",
        "pg_switch_xlog",
        "pg_create_restore_point",
        "pg_drop_replication_slot",
        "pg_create_physical_replication_slot",
        "pg_create_logical_replication_slot",
        "pg_replication_origin_create",
        "pg_backup_start",
        "pg_backup_stop",
        "pg_start_backup",
        "pg_stop_backup",
        "pg_stat_reset",
        "pg_stat_reset_shared",
        "pg_stat_reset_single_table_counters",
        "pg_stat_reset_single_function_counters",
        "pg_stat_reset_slru",
        "pg_stat_reset_replication_slot",
        "pg_stat_get_activity",
        "pg_stat_get_backend_activity",
        "pg_stat_get_backend_pid",
        "pg_stat_get_backend_dbid",
        "pg_stat_get_backend_userid",
        "pg_stat_get_backend_activity_start",
        "pg_stat_get_backend_client_addr",
        "pg_stat_get_backend_client_port",
        "pg_database_size",
        "pg_tablespace_size",
        "pg_relation_size",
        "pg_total_relation_size",
        "pg_table_size",
        "pg_indexes_size",
        "pg_relation_filenode",
        "pg_filenode_relation",
        "pg_tablespace_location",
        "pg_get_userbyid",
        "pg_read_server_files",
        # --- replication / WAL state control & introspection ---
        "pg_replication_origin_drop",
        "pg_replication_origin_session_setup",
        "pg_replication_origin_xact_setup",
        "pg_replication_origin_advance",
        "pg_replication_slot_advance",
        "pg_logical_emit_message",
        "pg_notify",
        # --- WAL / recovery position & replication-state introspection (recon:
        #     leak WAL LSN/segment names, recovery/standby status, replay lag).
        #     The pg_*-function prefix gate in checks/functions.py is the real
        #     backstop; these are enumerated for clarity/auditability. ---
        "pg_current_wal_lsn",
        "pg_current_wal_insert_lsn",
        "pg_current_wal_flush_lsn",
        "pg_walfile_name",
        "pg_walfile_name_offset",
        "pg_wal_lsn_diff",
        "pg_last_wal_receive_lsn",
        "pg_last_wal_replay_lsn",
        "pg_last_xact_replay_timestamp",
        "pg_is_in_recovery",
        "pg_is_wal_replay_paused",
        "pg_get_wal_replay_pause_state",
        "pg_get_replication_slots",
        "pg_get_wal_resource_managers",
        "pg_postmaster_start_time",
        "pg_conf_load_time",
        # --- per-relation / per-backend C-level statistics accessors. The
        #     pg_stat_get_* family exposes live tuple/IO/scan counters for ANY
        #     relation OID (incl. out-of-allowlist objects) and is the functional
        #     equivalent of reading pg_stat_*; covered by the prefix gate too. ---
        "pg_stat_get_tuples_inserted",
        "pg_stat_get_tuples_updated",
        "pg_stat_get_tuples_deleted",
        "pg_stat_get_tuples_returned",
        "pg_stat_get_tuples_fetched",
        "pg_stat_get_live_tuples",
        "pg_stat_get_dead_tuples",
        "pg_stat_get_numscans",
        "pg_stat_get_blocks_fetched",
        "pg_stat_get_blocks_hit",
        "pg_stat_get_db_numbackends",
        "pg_stat_get_db_xact_commit",
        # --- catalog/config inspection functions usable as a FROM/LATERAL source ---
        "pg_config",
        "pg_get_keywords",
        "pg_settings",
        "pg_hba_file_rules",
        "pg_ident_file_mappings",
        "pg_file_settings",
        "pg_show_all_settings",
        "pg_show_all_file_settings",
        "pg_logical_slot_get_changes",
        "pg_logical_slot_peek_changes",
        "pg_logical_slot_get_binary_changes",
        "pg_logical_slot_peek_binary_changes",
        "pg_wal_replay_pause",
        "pg_wal_replay_resume",
        "pg_xlog_replay_pause",
        "pg_xlog_replay_resume",
        "pg_control_system",
        "pg_control_checkpoint",
        "pg_control_recovery",
        "pg_control_init",
        # --- object identity / definition introspection (no table ref needed) ---
        "pg_describe_object",
        "pg_identify_object",
        "pg_identify_object_as_address",
        "pg_get_object_address",
        "pg_get_function_arguments",
        "pg_get_function_identity_arguments",
        "pg_get_function_result",
        "pg_get_functiondef",
        "row_security_active",
        # --- catalog definition dumpers (leak schema of out-of-allowlist objects
        #     by OID/regclass; need NO table reference, so the table allowlist
        #     never engages). FKs/CHECKs expose relationships & business logic. ---
        "pg_get_constraintdef",
        "pg_get_indexdef",
        "pg_get_viewdef",
        "pg_get_triggerdef",
        "pg_get_ruledef",
        "pg_get_partkeydef",
        "pg_get_statisticsobjdef",
        "pg_get_expr",
        "pg_get_serial_sequence",
        # --- object/privilege introspection (probe existence/perms of
        #     out-of-allowlist objects; take no table reference so the table
        #     allowlist never engages) ---
        # to_reg*() resolves a catalog object (relation/role/type/proc/operator/
        # text-search config/collation) from a STRING LITERAL by name — it takes
        # no table reference, so the table allowlist never engages and this denylist
        # is the only defense. Kept symmetric with _BLOCKED_CAST_TYPES in
        # checks/functions.py, which blocks the identical `'x'::regrole` cast form.
        "to_regclass",
        "to_regnamespace",
        "to_regtype",
        "to_regproc",
        "to_regprocedure",
        "to_regrole",
        "to_regoper",
        "to_regoperator",
        "to_regconfig",
        "to_regdictionary",
        "to_regcollation",
        "has_table_privilege",
        "has_column_privilege",
        "has_database_privilege",
        "has_schema_privilege",
        "has_sequence_privilege",
        "pg_has_role",
        "schema_to_xml",
        "schema_to_xmlschema",
        "table_to_xmlschema",
        "cursor_to_xmlschema",
        "currval",
        "pg_export_snapshot",
        "pg_blocking_pids",
        "pg_log_backend_memory_contexts",
        "pg_ls_logicalmapdir",
        "pg_ls_logicalsnapdir",
        # --- identity / version / schema / txid reconnaissance ---
        # No-arg/idempotent built-ins that fingerprint the server, current
        # principal, current database/schema, or transaction-id state. They take
        # NO table reference, so the table allowlist never engages and this
        # denylist (plus the bare-keyword Column scan in checks/functions.py for
        # the spellings that parse without parens) is the only defense. Matched on
        # the AST function name, case-folded. Note: `version()` parses to the typed
        # CurrentVersion node whose sql_name() is "current_version", so BOTH
        # spellings are listed. now()/current_date/current_timestamp/pg_typeof
        # resolve to distinct names and are unaffected (verified — no FP).
        "current_database",
        "current_catalog",
        "current_schema",
        "current_schemas",
        "current_user",
        "session_user",
        "current_role",
        "user",
        "version",
        "current_version",
        "current_query",
        "txid_current",
        "txid_current_if_assigned",
        "txid_current_snapshot",
        "txid_status",
        "txid_snapshot_xmin",
        "txid_snapshot_xmax",
        "txid_snapshot_xip",
        "txid_visible_in_snapshot",
        "pg_current_xact_id",
        "pg_current_xact_id_if_assigned",
        "pg_current_snapshot",
        "pg_snapshot_xmin",
        "pg_snapshot_xmax",
        "pg_snapshot_xip",
        "pg_visible_in_snapshot",
        # --- configuration read/write (info disclosure / state change) ---
        "set_config",
        "current_setting",
        # --- sequence state mutation ---
        "setval",
        "nextval",
        # --- advisory locks (hold server resources) ---
        "pg_advisory_lock",
        "pg_advisory_lock_shared",
        "pg_advisory_xact_lock",
        "pg_advisory_xact_lock_shared",
        "pg_advisory_unlock",
        "pg_advisory_unlock_all",
        "pg_try_advisory_lock",
        "pg_try_advisory_lock_shared",
        "pg_try_advisory_xact_lock",
        "pg_try_advisory_xact_lock_shared",
        "pg_advisory_unlock_shared",
        # --- query-to-XML exfiltration (runs arbitrary SQL text) ---
        "query_to_xml",
        "query_to_xmlschema",
        "query_to_xml_and_xmlschema",
        "database_to_xml",
        "database_to_xmlschema",
        "table_to_xml",
        "cursor_to_xml",
    }
)


# System catalogs / metadata schemas that leak credentials, role lists, server
# config, or the full schema of out-of-allowlist objects. Reading any of these is
# a reconnaissance/exfiltration move, never a legitimate analytics read — so they
# are blocked even when allowed_tables is None (no allowlist configured). Matched
# on the normalized AST table reference, never the raw string.
#
# Two layers:
#   * schema-qualified probes: anything under pg_catalog.* or information_schema.*
#     (e.g. pg_catalog.pg_class, information_schema.columns) — matched by db name.
#   * bare catalog VIEWS that live in pg_catalog but are usually referenced
#     unqualified (e.g. `FROM pg_authid`, `FROM pg_shadow`). These are the
#     high-value credential/role/config relations.
# pg_catalog/information_schema (PostgreSQL/SQL-standard) + cross-dialect metadata schemas.
# MySQL reserves the `mysql` (system tables incl. `mysql.user` credential store) and
# `performance_schema` schema names; no application uses them, so blocking the schema is
# the FP-safe counterpart to pg_catalog.* and catches `FROM mysql.user` UNION recon on a
# MySQL backend / fallback. (`sys` is intentionally NOT listed — too short / app-collision
# risk; MySQL/MSSQL `sys.*` recon is left as a documented gap rather than risk benign FP.)
SYSTEM_CATALOG_SCHEMAS: frozenset[str] = frozenset(
    {"pg_catalog", "information_schema", "mysql", "performance_schema"}
)

DEFAULT_BLOCKED_CATALOG_TABLES: frozenset[str] = frozenset(
    {
        # credentials / password hashes
        "pg_authid",
        "pg_shadow",
        # roles / users
        "pg_roles",
        "pg_user",
        "pg_group",
        "pg_auth_members",
        "pg_user_mappings",
        "pg_user_mapping",
        # server configuration / files / HBA
        "pg_settings",
        "pg_file_settings",
        "pg_hba_file_rules",
        "pg_ident_file_mappings",
        "pg_config",
        # schema / relationship introspection (whole-catalog recon)
        "pg_class",
        "pg_attribute",
        "pg_namespace",
        "pg_proc",
        "pg_database",
        "pg_tables",
        "pg_views",
        "pg_indexes",
        "pg_matviews",
        "pg_sequences",
        "pg_type",
        "pg_index",
        "pg_constraint",
        "pg_attrdef",
        "pg_depend",
        "pg_description",
        "pg_inherits",
        "pg_foreign_table",
        "pg_foreign_server",
        "pg_foreign_data_wrapper",
        # runtime / statistics views (recon: live queries, table/column stats,
        # I/O counters — enumerate every relation incl. out-of-allowlist objects).
        # The pg_* prefix rule in check_catalog() is the real backstop; these are
        # listed for clarity/auditability.
        "pg_stat_activity",
        "pg_stat_replication",
        "pg_stat_user_tables",
        "pg_stat_user_indexes",
        "pg_stat_all_tables",
        "pg_stat_all_indexes",
        "pg_stat_sys_tables",
        "pg_stat_sys_indexes",
        "pg_stat_xact_user_tables",
        "pg_stat_database",
        "pg_stat_bgwriter",
        "pg_statio_user_tables",
        "pg_statio_user_indexes",
        "pg_statio_all_tables",
        "pg_statio_all_indexes",
        "pg_stats",
        "pg_stats_ext",
        "pg_locks",
        "pg_prepared_statements",
        "pg_prepared_xacts",
        "pg_cursors",
        "pg_replication_slots",
        "pg_publication",
        "pg_subscription",
        # large-object byte store (read raw object bytes / enumerate object OIDs)
        "pg_largeobject",
        "pg_largeobject_metadata",
        # --- cross-dialect system catalogs (Oracle / MSSQL / MySQL) ---
        # PostgreSQL is the target, but real-world UNION-based recon payloads (and the
        # external SQLi corpora) lift the version/schema views from OTHER engines
        # verbatim: `UNION SELECT banner FROM v$version`, `UNION SELECT name FROM
        # sysobjects`, `FROM dual`, `FROM all_tables`. They parse here as ordinary
        # bare tables and would otherwise slip the pg_*-only catalog gate. No PG app
        # table legitimately carries these reserved names (verified zero hits in the
        # external benign set), so block them as the cross-engine counterpart to the
        # pg_catalog denylist. (`v$...` is also covered by the v$ prefix gate below.)
        "v$version",        # Oracle version banner (classic UNION recon target)
        "v$session",        # Oracle live sessions
        "v$instance",       # Oracle instance info
        "v$database",       # Oracle database info
        "v$parameter",      # Oracle server parameters
        "dual",             # Oracle dummy table — recon scaffolding for UNION/subselect
        "all_tables",       # Oracle schema enumeration
        "user_tables",      # Oracle schema enumeration (current user)
        "all_tab_columns",  # Oracle column enumeration
        "all_users",        # Oracle user enumeration
        "sysobjects",       # MSSQL object catalog (UNION recon target)
        "syscolumns",       # MSSQL column catalog
        "sysusers",         # MSSQL user catalog
        "sysdatabases",     # MSSQL database catalog
        "systables",        # generic/DB2 table catalog
    }
)

# Any relation whose bare (unqualified or pg_catalog-qualified) name starts with one
# of these reserved PostgreSQL prefixes is a system catalog / statistics / introspection
# view, never an application table. PostgreSQL reserves the ``pg_`` prefix for system
# objects (creating a user table with it raises a warning), so a prefix gate closes the
# whole ``pg_stat_*`` / ``pg_statio_*`` / ``pg_*`` recon family without enumerating every
# version-specific view. Schema-qualified user tables in a NON-catalog schema
# (``app.pg_foo``) are unaffected — the catalog check only applies the prefix when the
# reference is unqualified or already in a catalog schema.
SYSTEM_CATALOG_NAME_PREFIXES: tuple[str, ...] = ("pg_", "v$", "v_$")

# Reserved prefixes for built-in FUNCTION names. PostgreSQL reserves ``pg_`` for
# system objects, so any function named ``pg_*`` is a built-in introspection /
# admin / replication / file / WAL accessor — never an application function. A
# fail-CLOSED prefix gate in checks/functions.py blocks every ``pg_*`` call NOT in
# the small benign allowlist below, so the recon family (pg_current_wal_*,
# pg_is_in_recovery, pg_stat_get_*, pg_walfile_name, …) is covered without
# enumerating each version-specific function in DEFAULT_BLOCKED_FUNCTIONS. This is
# the symmetric counterpart to SYSTEM_CATALOG_NAME_PREFIXES for tables.
BLOCKED_FUNCTION_PREFIXES: tuple[str, ...] = ("pg_",)

# pg_* built-ins that are harmless in an analytics/read context and must stay
# allowed so the prefix gate does not destroy recall. These take no file/network/
# admin action and leak no credentials, schema, or replication state: pure type/
# size/formatting helpers and the trivial client-context accessor. Matched on the
# exact, case-folded function name.
ALLOWED_PG_FUNCTIONS: frozenset[str] = frozenset(
    {
        "pg_typeof",            # type name of an expression (formatting helper)
        "pg_size_pretty",       # bytes -> human string (no relation reference)
        "pg_size_bytes",        # human string -> bytes
        "pg_backend_pid",       # this session's PID (own context only)
        "pg_client_encoding",   # this session's client encoding
        "pg_column_size",       # on-disk size of a VALUE expression (no OID probe)
        "pg_collation_for",     # collation of an expression
        "pg_jsonb_pretty",      # pretty-print a jsonb value
        "pg_input_is_valid",    # validate a literal against a type
    }
)

# Column names that are sensitive regardless of table — secrets, government IDs,
# payment data. Read of any of these is BLOCKED by default. Matched on the exact,
# case-folded column NAME (not a substring) so ordinary columns like
# `password_changed_at` or `card_type` do NOT over-fire. Korean keys (주민/주민등록번호)
# are matched literally. Tune via GuardPolicy.sensitive_columns (empty = disabled).
DEFAULT_SENSITIVE_COLUMNS: frozenset[str] = frozenset(
    {
        # --- passwords ---
        "password",
        "passwd",
        "password_hash",
        "passwordhash",
        "pwd",
        "authentication_string",  # MySQL: password hash column in mysql.user
        # --- auth tokens / session secrets ---
        "auth_token",
        "session_token",
        "refresh_token",
        "access_token",
        "api_key",
        "apikey",
        "secret",
        "secret_key",
        "secretkey",
        "account_secret",
        "client_secret",
        "otp_secret",
        "totp_secret",
        "salt",
        "private_key",
        "privatekey",
        # --- recovery / one-time codes / PINs ---
        "recovery_code",
        "backup_code",
        "backup_codes",
        "otp",
        "otp_code",
        "pin",
        "pin_code",
        "pincode",
        "security_code",
        # --- government IDs ---
        "ssn",
        "social_security_number",
        "주민",
        "주민번호",
        "주민등록번호",
        "resident_registration_number",
        "passport_number",
        "passport_no",
        "passportnumber",
        "drivers_license",
        "driver_license",
        "drivers_license_number",
        "driver_license_number",
        "license_number",
        # --- payment / banking ---
        "credit_card",
        "creditcard",
        "card_no",
        "card_number",
        "cardnumber",
        "cvv",
        "cvc",
        "cvv2",
        "bank_account_number",
        "bank_account_no",
        "routing_number",
        "routing_no",
        "iban",
        "swift_code",
    }
)


class GuardPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    # Bound untrusted input before it reaches sqlglot. Byte length is measured as
    # UTF-8 because Python character counts understate multibyte SQL input.
    max_query_chars: int = Field(default=100_000, ge=1)
    max_query_bytes: int = Field(default=400_000, ge=1)

    # --- parsing dialect ---
    # Primary sqlglot dialect — 배포 DB 에 맞춰 설정(MySQL 이면 "mysql", MSSQL 이면 "tsql" 등).
    # 위험 검사(denylist)는 cross-dialect 라 파싱만 다이얼렉트별이다.
    dialect: str = "postgres"
    # 폴백은 **기본 비활성(())**. postgres 배포에서 비-postgres 구문은 보통 잘못 생성된 SQL 이라
    # fail-closed BLOCK 이 올바른 방어다(폴백을 켜면 그런 악성/오류 구문을 타 다이얼렉트로 파싱해
    # 통과시킬 수 있어 attack recall 이 떨어짐). 다중 다이얼렉트 입력이 정상인 환경에서만 명시적으로
    # 켠다: ``GuardPolicy(fallback_dialects=("mysql","tsql","sqlite"))``.
    fallback_dialects: tuple[str, ...] = ()

    read_only: bool = True
    allow_insert: bool = False
    allow_update: bool = False
    allow_delete: bool = False
    allow_ddl: bool = False

    # None = any table allowed. {"orders": []} = table allowed, all columns allowed.
    # {"orders": ["id", "status"]} = table allowed, only those columns allowed.
    # Keys may be bare ("orders") or schema-qualified ("public.orders").
    allowed_tables: dict[str, list[str]] | None = None

    require_where_on_write: bool = True
    default_limit: int | None = 1000
    max_limit: int | None = 10000
    block_cartesian: bool = True
    block_tautology: bool = True
    # Block inferential / UNION-based SQLi probes (checks/inference.py): an
    # uncorrelated scalar subquery compared to a constant or a constant-truth
    # EXISTS in a row filter (blind-SQLi oracle), and a set-operation arm that
    # projects a bare '*' (whole-row UNION exfiltration). Verified to add zero
    # false-blocks on benign analytics SQL. Set False to disable.
    block_inference_probe: bool = True
    blocked_functions: frozenset[str] = DEFAULT_BLOCKED_FUNCTIONS

    # pg_*-function prefix gate (fail-closed). When True, ANY function named pg_*
    # that is not in allowed_pg_functions is blocked, even if it is not enumerated
    # in blocked_functions — the symmetric counterpart to the pg_* table-prefix gate
    # in checks/catalog.py. Set False to fall back to the enumerated denylist only.
    block_pg_function_prefix: bool = True
    allowed_pg_functions: frozenset[str] = ALLOWED_PG_FUNCTIONS

    # System-catalog probe defense. Reads of pg_catalog.* / information_schema.*
    # and the bare credential/role/config catalog views below are BLOCKED even when
    # allowed_tables is None. Set block_system_catalogs=False to opt out (e.g. a
    # trusted admin/introspection context), or extend blocked_catalog_tables.
    block_system_catalogs: bool = True
    blocked_catalog_tables: frozenset[str] = DEFAULT_BLOCKED_CATALOG_TABLES

    # Sensitive-column denylist. Reading any column whose name (case-folded, exact)
    # is in this set is BLOCKED regardless of the table — independent of the table
    # allowlist, so it also catches `... UNION SELECT password FROM users` and
    # whole-row serialization (to_jsonb/row_to_json) of a table that has one of
    # these columns. Set to an empty frozenset() to disable.
    sensitive_columns: frozenset[str] = DEFAULT_SENSITIVE_COLUMNS

    # --- Tier-2: EXPLAIN cost guard (opt-in, used by ko_sqlguard.cost) ---
    # Enforced only when you call the cost guard with a DB connection; the
    # deterministic check() never reads these.
    cost_threshold: float | None = None  # block if planner Total Cost exceeds this
    max_estimated_rows: int | None = None  # block if planner Plan Rows exceeds this

    # --- Tier-2 seam: not enforced in v1 ---
    pii_columns: dict[str, list[str]] | None = None

    # Block-violations below this severity are downgraded to advisory warns. The
    # table allowlist (table_not_allowed) and column allowlist (column_not_allowed)
    # are HIGH, so a security-sensitive deployment can keep them enforced at
    # min_block_severity=HIGH. Tautology/cartesian heuristics are MEDIUM and become
    # advisory above MEDIUM; setting this to CRITICAL disables the allowlists too —
    # do that only for a fully trusted caller.
    min_block_severity: Severity = Severity.MEDIUM

    @model_validator(mode="after")
    def _writes_require_not_read_only(self) -> GuardPolicy:
        if self.read_only and (
            self.allow_insert or self.allow_update or self.allow_delete or self.allow_ddl
        ):
            raise ValueError(
                "read_only=True conflicts with allow_insert/update/delete/ddl; "
                "set read_only=False explicitly to permit writes"
            )
        return self

    @model_validator(mode="after")
    def _limits_sane(self) -> GuardPolicy:
        for name in ("default_limit", "max_limit"):
            value = getattr(self, name)
            if value is not None and value < 1:
                raise ValueError(f"{name} must be >= 1 or None")
        return self

    def validate_production(self) -> GuardPolicy:
        """Validate the explicit table-allowlist contract for a production policy.

        ``allowed_tables={}`` is valid and intentionally means deny all table
        access. ``None`` remains supported for backwards compatibility, but is
        unsuitable for deployments that require an allowlist.
        """
        if self.allowed_tables is None:
            raise ValueError(
                "production policy requires an explicit allowed_tables mapping; "
                "use {} to deny all table access"
            )
        if self.min_block_severity > Severity.HIGH:
            raise ValueError(
                "production policy requires min_block_severity <= HIGH so "
                "table and column allowlist violations block"
            )
        return self

    normalized_allowed: dict[str, frozenset[str] | None] | None = Field(
        default=None, exclude=True, repr=False
    )

    @model_validator(mode="after")
    def _normalize_allowlist(self) -> GuardPolicy:
        """Pre-fold allowlist keys/columns to PostgreSQL's unquoted-identifier case."""
        if self.allowed_tables is None:
            object.__setattr__(self, "normalized_allowed", None)
            return self
        normalized: dict[str, frozenset[str] | None] = {}
        for table, columns in self.allowed_tables.items():
            key = table.strip().lower()
            normalized[key] = frozenset(c.strip().lower() for c in columns) if columns else None
        object.__setattr__(self, "normalized_allowed", normalized)
        return self

    # Pre-folded denylists used by checks/catalog.py. Excluded from repr/serialization.
    normalized_catalog_schemas: frozenset[str] = Field(
        default_factory=frozenset, exclude=True, repr=False
    )
    normalized_catalog_tables: frozenset[str] = Field(
        default_factory=frozenset, exclude=True, repr=False
    )
    normalized_sensitive_columns: frozenset[str] = Field(
        default_factory=frozenset, exclude=True, repr=False
    )
    normalized_catalog_prefixes: tuple[str, ...] = Field(
        default_factory=tuple, exclude=True, repr=False
    )
    normalized_function_prefixes: tuple[str, ...] = Field(
        default_factory=tuple, exclude=True, repr=False
    )
    normalized_allowed_pg_functions: frozenset[str] = Field(
        default_factory=frozenset, exclude=True, repr=False
    )

    @model_validator(mode="after")
    def _normalize_denylists(self) -> GuardPolicy:
        """Case-fold catalog/sensitive denylists once so checks compare cheaply."""
        object.__setattr__(
            self, "normalized_catalog_schemas", frozenset(s.lower() for s in SYSTEM_CATALOG_SCHEMAS)
        )
        object.__setattr__(
            self,
            "normalized_catalog_tables",
            frozenset(t.strip().lower() for t in self.blocked_catalog_tables),
        )
        object.__setattr__(
            self,
            "normalized_sensitive_columns",
            frozenset(c.strip().lower() for c in self.sensitive_columns),
        )
        object.__setattr__(
            self,
            "normalized_catalog_prefixes",
            tuple(p.strip().lower() for p in SYSTEM_CATALOG_NAME_PREFIXES if p.strip()),
        )
        object.__setattr__(
            self,
            "normalized_function_prefixes",
            tuple(p.strip().lower() for p in BLOCKED_FUNCTION_PREFIXES if p.strip()),
        )
        object.__setattr__(
            self,
            "normalized_allowed_pg_functions",
            frozenset(f.strip().lower() for f in self.allowed_pg_functions),
        )
        return self
