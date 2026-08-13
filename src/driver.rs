use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use futures_util::TryStreamExt;
use serde_json::{json, Map, Value};
use tiberius::time::chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime};
use tiberius::{AuthMethod, Client, ColumnData, Config, FromSql, QueryItem};
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tokio::sync::Mutex as AsyncMutex;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

use crate::abi::{self, IrodoriConnectorBuffer};
use crate::{ABI_VERSION, CONFIG_JSON, DRIVER_LINKED, ENGINE, MANIFEST_JSON};

type TdsClient = Client<Compat<TcpStream>>;

static CONNECTIONS: OnceLock<Mutex<HashMap<String, SqlServerConnection>>> = OnceLock::new();
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

#[derive(Clone)]
struct SqlServerConnection {
    client: Arc<AsyncMutex<TdsClient>>,
    config: SqlServerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqlServerConfig {
    ado: Option<String>,
    host: String,
    port: u16,
    database: Option<String>,
    user: Option<String>,
    password: Option<String>,
    /// A Microsoft Entra (Azure AD) access token, when the profile supplies one
    /// instead of a SQL login.
    access_token: Option<String>,
    redaction_values: Vec<String>,
}

#[derive(Default)]
struct ObjectMeta {
    kind: String,
    columns: Vec<Value>,
}

type QueryRows = Vec<Vec<Value>>;
type QueryOutput = (Vec<String>, QueryRows, bool);

fn connections() -> &'static Mutex<HashMap<String, SqlServerConnection>> {
    CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn runtime() -> Result<&'static Runtime, String> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = Runtime::new().map_err(|err| format!("create tokio runtime failed: {err}"))?;
    let _ = RUNTIME.set(runtime);
    RUNTIME
        .get()
        .ok_or_else(|| "create tokio runtime failed.".to_string())
}

pub fn call_json(request: IrodoriConnectorBuffer) -> IrodoriConnectorBuffer {
    let request = match abi::parse_request(request) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let method = match abi::request_method(request.as_ref()) {
        Ok(method) => method,
        Err(response) => return response,
    };

    match method {
        "health" | "ping" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
        ])),
        "describe" | "capabilities" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
            (
                "manifest".to_string(),
                serde_json::from_str(MANIFEST_JSON).unwrap_or(Value::Null),
            ),
            (
                "config".to_string(),
                serde_json::from_str(CONFIG_JSON).unwrap_or(Value::Null),
            ),
        ])),
        "manifest" => abi::owned_buffer(MANIFEST_JSON.to_string()),
        "config" => abi::owned_buffer(CONFIG_JSON.to_string()),
        "connect" => connect(request.as_ref().expect("connect has request")),
        "query" => query(request.as_ref().expect("query has request")),
        "metadata" => metadata(request.as_ref().expect("metadata has request")),
        "close" => close(request.as_ref().expect("close has request")),
        other => abi::error(
            "connector.unknownMethod",
            format!("unknown connector method: {other}"),
        ),
    }
}

fn connect(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let config = match SqlServerConfig::from_request(request) {
        Ok(config) => config,
        Err(err) => return abi::error("connector.invalidRequest", err),
    };
    let connection =
        match runtime().and_then(|runtime| runtime.block_on(SqlServerConnection::new(config))) {
            Ok(connection) => connection,
            Err(err) => return abi::error("connector.connectFailed", err),
        };
    let version = match runtime().and_then(|runtime| runtime.block_on(load_version(&connection))) {
        Ok(version) => version,
        Err(err) => return abi::error("connector.connectFailed", connection.config.redact(&err)),
    };

    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let mut response = Map::from_iter([
        ("engine".to_string(), Value::String(ENGINE.to_string())),
        (
            "connectionId".to_string(),
            Value::String(connection_id.clone()),
        ),
        ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
        (
            "host".to_string(),
            Value::String(connection.config.host.clone()),
        ),
        ("port".to_string(), json!(connection.config.port)),
        ("serverVersion".to_string(), Value::String(version)),
    ]);
    if let Some(database) = connection.config.database.as_deref() {
        response.insert("database".to_string(), Value::String(database.to_string()));
    }
    guard.insert(connection_id, connection);
    abi::ok(response)
}

fn query(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let Some(sql) = abi::string_field(request, "sql")
        .or_else(|| abi::string_field(request, "query"))
        .or_else(|| abi::string_field(request, "statement"))
    else {
        return abi::error(
            "connector.invalidRequest",
            "query requires a string sql, query, or statement field.",
        );
    };
    let connection = match connection(&connection_id) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    match runtime()
        .and_then(|runtime| runtime.block_on(run_query(&connection, sql, abi::max_rows(request))))
    {
        Ok((columns, rows, truncated)) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            (
                "columns".to_string(),
                Value::Array(columns.into_iter().map(Value::String).collect()),
            ),
            (
                "rows".to_string(),
                Value::Array(rows.into_iter().map(Value::Array).collect()),
            ),
            ("truncated".to_string(), Value::Bool(truncated)),
        ])),
        Err(err) => abi::error("connector.queryFailed", connection.config.redact(&err)),
    }
}

fn metadata(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let connection = match connection(&connection_id) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    match runtime().and_then(|runtime| runtime.block_on(load_metadata(&connection))) {
        Ok(metadata) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            ("metadata".to_string(), metadata),
        ])),
        Err(err) => abi::error("connector.metadataFailed", connection.config.redact(&err)),
    }
}

fn close(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let existed = guard.remove(&connection_id).is_some();
    abi::ok(Map::from_iter([
        ("connectionId".to_string(), Value::String(connection_id)),
        ("closed".to_string(), Value::Bool(existed)),
    ]))
}

impl SqlServerConnection {
    async fn new(config: SqlServerConfig) -> Result<Self, String> {
        let tds_config = config.tds_config()?;
        let tcp = TcpStream::connect(tds_config.get_addr())
            .await
            .map_err(|err| config.redact(&format!("connect failed: {err}")))?;
        let _ = tcp.set_nodelay(true);
        let client = Client::connect(tds_config, tcp.compat_write())
            .await
            .map_err(|err| config.redact(&format!("connect failed: {err}")))?;
        Ok(Self {
            client: Arc::new(AsyncMutex::new(client)),
            config,
        })
    }
}

impl SqlServerConfig {
    fn from_request(request: &Value) -> Result<Self, String> {
        let ado = option_string(request, &["connectionString", "url", "dsn"]);
        let host = option_string(request, &["host", "server"])
            .unwrap_or_else(|| host_from_ado(ado.as_deref()).unwrap_or_else(|| "localhost".into()));
        let port = option_string(request, &["port"])
            .and_then(|value| value.parse::<u16>().ok())
            .unwrap_or(1433);
        let database = option_string(request, &["database", "db"]);
        let user = option_string(request, &["user", "username", "uid"]);
        let password = option_string(request, &["password", "pwd", "token"]);
        // Every Entra path — interactive login, a service principal, a managed
        // identity — ends in a token. Accepting the token itself is the part
        // this connector can honour without an Azure identity client.
        let access_token = option_string(
            request,
            &[
                "accessToken",
                "aadToken",
                "azureAccessToken",
                "entraToken",
                "token",
            ],
        );
        let mut redaction_values = Vec::new();
        push_sensitive(&mut redaction_values, access_token.as_deref());
        push_sensitive(&mut redaction_values, password.as_deref());
        collect_ado_secrets(ado.as_deref().unwrap_or_default(), &mut redaction_values);
        Ok(Self {
            ado,
            host,
            port,
            database,
            user,
            password,
            access_token,
            redaction_values,
        })
    }

    fn tds_config(&self) -> Result<Config, String> {
        let mut config = if let Some(ado) = self.ado.as_deref() {
            Config::from_ado_string(ado).map_err(|err| format!("bad connection string: {err}"))?
        } else {
            let mut config = Config::new();
            config.host(&self.host);
            config.port(self.port);
            // An Entra token identifies a user or service principal that SQL
            // Server trusts directly, so it replaces the SQL login rather than
            // supplementing it. Preferred when present: supplying both and
            // silently using the password would authenticate as somebody else.
            match self.access_token.as_deref() {
                Some(token) => config.authentication(AuthMethod::AADToken(token.to_string())),
                None => config.authentication(AuthMethod::sql_server(
                    self.user.clone().unwrap_or_default(),
                    self.password.clone().unwrap_or_default(),
                )),
            }
            if let Some(database) = self.database.as_deref() {
                config.database(database);
            }
            config
        };
        config.trust_cert();
        Ok(config)
    }

    fn redact(&self, message: &str) -> String {
        // `str::replace` with an empty needle inserts the replacement between
        // every character, so a profile configured by host and port — which has
        // no ADO string — turned every error message into
        // `<sqlserver-connection>l<sqlserver-connection>o…`. The loop below
        // already guarded against an empty secret; this one was missed.
        let message = match self.ado.as_deref().filter(|ado| !ado.is_empty()) {
            Some(ado) => message.replace(ado, "<sqlserver-connection>"),
            None => message.to_string(),
        };
        self.redaction_values
            .iter()
            .fold(message, |message, secret| {
                if secret.is_empty() {
                    message
                } else {
                    message.replace(secret, "****")
                }
            })
    }
}

async fn load_version(connection: &SqlServerConnection) -> Result<String, String> {
    let mut guard = connection.client.lock().await;
    let stream = guard
        .query("select @@version", &[])
        .await
        .map_err(|err| format!("version query failed: {err}"))?;
    let row = stream
        .into_row()
        .await
        .map_err(|err| format!("version query failed: {err}"))?
        .ok_or_else(|| "version query returned no rows.".to_string())?;
    let banner: Option<&str> = row
        .try_get(0)
        .map_err(|err| format!("version decode failed: {err}"))?;
    Ok(banner
        .map(|value| value.lines().next().unwrap_or(value).trim().to_string())
        .unwrap_or_else(|| "SQL Server".to_string()))
}

async fn run_query(
    connection: &SqlServerConnection,
    sql: &str,
    cap: usize,
) -> Result<QueryOutput, String> {
    let mut guard = connection.client.lock().await;
    let mut stream = guard
        .query(sql, &[])
        .await
        .map_err(|err| format!("query failed: {err}"))?;
    let mut columns = Vec::new();
    let mut rows = Vec::new();
    let mut truncated = false;
    while let Some(item) = stream
        .try_next()
        .await
        .map_err(|err| format!("query failed: {err}"))?
    {
        if let QueryItem::Row(row) = item {
            if columns.is_empty() {
                columns = row
                    .columns()
                    .iter()
                    .map(|column| column.name().to_string())
                    .collect();
            }
            if rows.len() < cap {
                rows.push(
                    row.cells()
                        .map(|(_, data)| column_data_to_json(data))
                        .collect(),
                );
            } else {
                truncated = true;
            }
        }
    }
    Ok((columns, rows, truncated))
}

async fn load_metadata(connection: &SqlServerConnection) -> Result<Value, String> {
    let mut guard = connection.client.lock().await;
    let mut schemas: BTreeMap<String, BTreeMap<String, ObjectMeta>> = BTreeMap::new();

    let mut objects = guard
        .query(
            "select table_schema, table_name, table_type \
             from information_schema.tables \
             where table_type in ('BASE TABLE', 'VIEW') \
               and table_schema not in ('INFORMATION_SCHEMA', 'sys') \
             order by table_schema, table_name",
            &[],
        )
        .await
        .map_err(|err| format!("metadata objects failed: {err}"))?;
    while let Some(item) = objects
        .try_next()
        .await
        .map_err(|err| format!("metadata objects failed: {err}"))?
    {
        if let QueryItem::Row(row) = item {
            let schema = get_str(&row, 0);
            let name = get_str(&row, 1);
            if name.is_empty() {
                continue;
            }
            let table_type = get_str(&row, 2);
            schemas.entry(schema).or_default().insert(
                name,
                ObjectMeta {
                    kind: if table_type.eq_ignore_ascii_case("VIEW") {
                        "view".to_string()
                    } else {
                        "table".to_string()
                    },
                    columns: Vec::new(),
                },
            );
        }
    }
    drop(objects);

    let mut columns_stream = guard
        .query(
            "select table_schema, table_name, column_name, data_type, is_nullable, \
                    ordinal_position, column_default \
             from information_schema.columns \
             where table_schema not in ('INFORMATION_SCHEMA', 'sys') \
             order by table_schema, table_name, ordinal_position",
            &[],
        )
        .await
        .map_err(|err| format!("metadata columns failed: {err}"))?;
    while let Some(item) = columns_stream
        .try_next()
        .await
        .map_err(|err| format!("metadata columns failed: {err}"))?
    {
        if let QueryItem::Row(row) = item {
            let schema = get_str(&row, 0);
            let table = get_str(&row, 1);
            let object = schemas
                .entry(schema)
                .or_default()
                .entry(table)
                .or_insert_with(|| ObjectMeta {
                    kind: "table".to_string(),
                    columns: Vec::new(),
                });
            let nullable = get_str(&row, 4);
            object.columns.push(json!({
                "name": get_str(&row, 2),
                "dataType": get_str(&row, 3),
                "nullable": nullable.eq_ignore_ascii_case("YES"),
                "ordinal": get_i32(&row, 5),
                "defaultValue": get_optional_str(&row, 6)
            }));
        }
    }

    Ok(json!({
        "schemas": schemas
            .into_iter()
            .map(|(schema, objects)| json!({
                "name": schema,
                "objects": objects
                    .into_iter()
                    .map(|(name, object)| json!({
                        "schema": schema,
                        "name": name,
                        "kind": object.kind,
                        "columns": object.columns,
                        "indexes": [],
                        "primaryKey": [],
                        "foreignKeys": []
                    }))
                    .collect::<Vec<_>>()
            }))
            .collect::<Vec<_>>()
    }))
}

fn column_data_to_json(data: &ColumnData<'static>) -> Value {
    match data {
        ColumnData::U8(value) => value.map_or(Value::Null, |value| json!(value)),
        ColumnData::I16(value) => value.map_or(Value::Null, |value| json!(value)),
        ColumnData::I32(value) => value.map_or(Value::Null, |value| json!(value)),
        ColumnData::I64(value) => value.map_or(Value::Null, |value| json!(value)),
        ColumnData::F32(value) => value.map_or(Value::Null, |value| json!(value)),
        ColumnData::F64(value) => value.map_or(Value::Null, |value| json!(value)),
        ColumnData::Bit(value) => value.map_or(Value::Null, Value::Bool),
        ColumnData::String(value) => value
            .as_ref()
            .map_or(Value::Null, |value| Value::String(value.to_string())),
        ColumnData::Guid(value) => {
            value.map_or(Value::Null, |value| Value::String(value.to_string()))
        }
        ColumnData::Binary(value) => value.as_ref().map_or(Value::Null, |value| {
            Value::String(format!("\\x{}", hex_encode(value)))
        }),
        ColumnData::Numeric(value) => value.map_or(Value::Null, |value| {
            Value::String(numeric_to_string(value.value(), value.scale()))
        }),
        ColumnData::Xml(value) => value
            .as_ref()
            .map_or(Value::Null, |value| Value::String(value.to_string())),
        ColumnData::DateTime(_) | ColumnData::SmallDateTime(_) | ColumnData::DateTime2(_) => {
            temporal(data, |value| {
                NaiveDateTime::from_sql(value)
                    .ok()
                    .flatten()
                    .map(|value| value.to_string())
            })
        }
        ColumnData::Date(_) => temporal(data, |value| {
            NaiveDate::from_sql(value)
                .ok()
                .flatten()
                .map(|value| value.to_string())
        }),
        ColumnData::Time(_) => temporal(data, |value| {
            NaiveTime::from_sql(value)
                .ok()
                .flatten()
                .map(|value| value.to_string())
        }),
        ColumnData::DateTimeOffset(_) => temporal(data, |value| {
            DateTime::<FixedOffset>::from_sql(value)
                .ok()
                .flatten()
                .map(|value| value.to_string())
        }),
    }
}

fn temporal(
    data: &ColumnData<'static>,
    decode: impl Fn(&ColumnData<'static>) -> Option<String>,
) -> Value {
    decode(data).map_or(Value::Null, Value::String)
}

fn numeric_to_string(value: i128, scale: u8) -> String {
    let scale = scale as usize;
    if scale == 0 {
        return value.to_string();
    }
    let digits = value.unsigned_abs().to_string();
    let padded = if digits.len() <= scale {
        format!("{}{digits}", "0".repeat(scale + 1 - digits.len()))
    } else {
        digits
    };
    let point = padded.len() - scale;
    let (int_part, frac_part) = padded.split_at(point);
    let sign = if value < 0 { "-" } else { "" };
    format!("{sign}{int_part}.{frac_part}")
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn get_str(row: &tiberius::Row, index: usize) -> String {
    get_optional_str(row, index).unwrap_or_default()
}

fn get_optional_str(row: &tiberius::Row, index: usize) -> Option<String> {
    row.try_get::<&str, _>(index)
        .ok()
        .flatten()
        .map(str::to_string)
}

fn get_i32(row: &tiberius::Row, index: usize) -> i32 {
    row.try_get::<i32, _>(index)
        .ok()
        .flatten()
        .or_else(|| row.try_get::<i16, _>(index).ok().flatten().map(i32::from))
        .unwrap_or_default()
}

fn connection(connection_id: &str) -> Result<SqlServerConnection, IrodoriConnectorBuffer> {
    let guard = connections().lock().map_err(|_| {
        abi::error(
            "connector.statePoisoned",
            "Connector connection state is poisoned.",
        )
    })?;
    guard.get(connection_id).cloned().ok_or_else(|| {
        abi::error(
            "connector.connectionNotFound",
            format!("no open connection: {connection_id}"),
        )
    })
}

fn request_containers(request: &Value) -> Vec<&Value> {
    [
        Some(request),
        request.get("profile"),
        request.get("options"),
        request.get("auth"),
        request.get("secrets"),
        request
            .get("profile")
            .and_then(|profile| profile.get("options")),
        request
            .get("profile")
            .and_then(|profile| profile.get("auth")),
        request
            .get("profile")
            .and_then(|profile| profile.get("secrets")),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn option_string(request: &Value, fields: &[&str]) -> Option<String> {
    request_containers(request)
        .into_iter()
        .find_map(|container| {
            fields.iter().find_map(|field| {
                container
                    .get(*field)
                    .map(|value| match value {
                        Value::String(value) => value.clone(),
                        Value::Number(value) => value.to_string(),
                        Value::Bool(value) => value.to_string(),
                        _ => String::new(),
                    })
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty())
            })
        })
}

fn push_sensitive(values: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        if !values.iter().any(|existing| existing == value) {
            values.push(value.to_string());
        }
    }
}

fn host_from_ado(ado: Option<&str>) -> Option<String> {
    ado?.split(';').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if matches!(
            key.trim().to_ascii_lowercase().as_str(),
            "server" | "data source" | "addr" | "address"
        ) {
            let value = value.trim().trim_start_matches("tcp:");
            Some(value.split(',').next().unwrap_or(value).trim().to_string())
        } else {
            None
        }
    })
}

fn collect_ado_secrets(ado: &str, values: &mut Vec<String>) {
    for part in ado.split(';') {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        if matches!(
            key.trim().to_ascii_lowercase().as_str(),
            "password" | "pwd" | "access token"
        ) {
            push_sensitive(values, Some(value));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_numeric_without_losing_scale() {
        assert_eq!(numeric_to_string(100, 2), "1.00");
        assert_eq!(numeric_to_string(-42, 3), "-0.042");
    }

    #[test]
    fn parses_profile_config() {
        let request = json!({
            "profile": {
                "host": "db.example.test",
                "port": 1434,
                "database": "app",
                "user": "sa",
                "password": "secret"
            }
        });
        let config = SqlServerConfig::from_request(&request).unwrap();
        assert_eq!(config.host, "db.example.test");
        assert_eq!(config.port, 1434);
        assert_eq!(config.database.as_deref(), Some("app"));
        assert_eq!(config.user.as_deref(), Some("sa"));
    }

    #[test]
    fn reads_an_entra_access_token_under_its_usual_names() {
        for field in ["accessToken", "aadToken", "azureAccessToken", "entraToken"] {
            let config = SqlServerConfig::from_request(&json!({
                "profile": { "host": "sql.local", "options": { field: "eyJ0oken" } }
            }))
            .expect("config");
            assert_eq!(config.access_token.as_deref(), Some("eyJ0oken"), "{field}");
        }
    }

    #[test]
    fn a_sql_login_profile_carries_no_token() {
        let config = SqlServerConfig::from_request(&json!({
            "profile": { "host": "sql.local", "user": "sa", "password": "pw" }
        }))
        .expect("config");
        assert_eq!(config.access_token, None);
        assert_eq!(config.password.as_deref(), Some("pw"));
    }

    #[test]
    fn the_token_is_redacted_from_errors() {
        // A token in a connection error would otherwise reach the log the user
        // pastes into an issue.
        let config = SqlServerConfig::from_request(&json!({
            "profile": { "host": "sql.local", "options": { "accessToken": "eyJ0oken" } }
        }))
        .expect("config");
        assert_eq!(
            config.redact("login failed for eyJ0oken"),
            "login failed for ****"
        );
    }

    #[test]
    fn a_profile_without_an_ado_string_does_not_mangle_the_message() {
        // Regression: `str::replace` with an empty needle inserts the
        // replacement between every character, so every error from a
        // host-and-port profile came back as
        // `<sqlserver-connection>l<sqlserver-connection>o…`.
        let config = SqlServerConfig::from_request(&json!({
            "profile": { "host": "sql.local", "user": "sa", "password": "pw" }
        }))
        .expect("config");
        assert_eq!(config.redact("login failed"), "login failed");
    }

    #[test]
    fn an_ado_string_is_still_replaced() {
        let config = SqlServerConfig::from_request(&json!({
            "profile": { "options": { "connectionString": "Server=sql.local;User Id=sa;Password=pw" } }
        }))
        .expect("config");
        let redacted = config.redact("cannot open Server=sql.local;User Id=sa;Password=pw");
        assert!(redacted.contains("<sqlserver-connection>"), "{redacted}");
        assert!(!redacted.contains("Password=pw"), "{redacted}");
    }
}
