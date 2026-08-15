use irodori_connector_abi::{option_bool, option_string, percent_encode, push_sensitive};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use futures_util::TryStreamExt;
use reqwest::Client as HttpClient;
use serde_json::{json, Map, Value};
use tiberius::time::chrono::{DateTime, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime};
use tiberius::{AuthMethod, Client, ColumnData, Config, EncryptionLevel, FromSql, QueryItem};
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
    tls: TlsTrust,
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
    let config = match runtime()
        .and_then(|runtime| runtime.block_on(SqlServerConfig::from_request(request)))
    {
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

/// How much the connector should believe the server it reaches.
///
/// This exists because the connector previously called `trust_cert()`
/// unconditionally: every connection accepted any certificate, and there was no
/// way to ask for verification. That matters more here than in most connectors
/// because an Entra access token is replayable — whoever terminates the TLS
/// session gets a credential that works against the real database.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct TlsTrust {
    /// A CA file to verify against, for a private or internal certificate
    /// authority. Verification stays on.
    ca_path: Option<String>,
    /// Explicitly accept any certificate. Named the same as everywhere else in
    /// the fleet so a user who knows one connector knows this one.
    accept_invalid_certs: bool,
    /// `None` leaves tiberius on its own default, which is
    /// `EncryptionLevel::Required` on a TLS-enabled build.
    encryption: Option<EncryptionLevel>,
}

impl TlsTrust {
    fn from_request(request: &Value) -> Self {
        Self {
            ca_path: option_string(
                request,
                &[
                    "sslRootCert",
                    "tlsCaCertificate",
                    "caCertificate",
                    "trustServerCertificateCa",
                ],
            ),
            accept_invalid_certs: option_bool(
                request,
                &[
                    "sslInsecure",
                    "tlsInsecure",
                    "trustServerCertificate",
                    "acceptInvalidCerts",
                ],
            )
            .unwrap_or(false),
            encryption: option_string(request, &["encrypt", "encryption", "sslMode"]).and_then(
                |value| match value.trim().to_ascii_lowercase().as_str() {
                    "required" | "require" | "strict" | "true" | "yes" => {
                        Some(EncryptionLevel::Required)
                    }
                    "on" | "prefer" | "preferred" => Some(EncryptionLevel::On),
                    // tiberius spells "encrypt the login only" as `Off`, which
                    // reads like "no encryption" and is not. A user writing
                    // `off` means no encryption, so that maps to NotSupported
                    // and only the explicit spelling selects login-only.
                    "login" | "loginonly" | "login-only" => Some(EncryptionLevel::Off),
                    "disable" | "disabled" | "notsupported" | "none" | "false" | "no" | "off" => {
                        Some(EncryptionLevel::NotSupported)
                    }
                    _ => None,
                },
            ),
        }
    }

    /// Apply the trust settings to a config.
    ///
    /// `Err` rather than a panic when the profile asks for both a CA and blanket
    /// trust: tiberius makes `trust_cert` and `trust_cert_ca` mutually exclusive
    /// and enforces it with `panic!`, so calling both would take the host down
    /// rather than return a message. `from_ado_string` can have set the CA
    /// already, which is how the previous unconditional `trust_cert()` crashed
    /// on exactly the connection strings that named a private CA.
    fn apply(&self, config: &mut Config, ado_names_ca: bool) -> Result<(), String> {
        if let Some(encryption) = self.encryption {
            config.encryption(encryption);
        }

        match (&self.ca_path, self.accept_invalid_certs, ado_names_ca) {
            (Some(_), true, _) | (None, true, true) => Err(
                "the profile both names a certificate authority and asks to accept any \
                 certificate. Choose one: drop the CA to accept anything, or drop the \
                 insecure option to verify against the CA."
                    .to_string(),
            ),
            // The connection string already pointed tiberius at a CA; touching
            // trust again from here is what panicked.
            (None, false, true) => Ok(()),
            (Some(path), false, _) => {
                if !std::path::Path::new(path).exists() {
                    return Err(format!(
                        "the certificate authority file at {path} does not exist."
                    ));
                }
                config.trust_cert_ca(path);
                Ok(())
            }
            (None, true, false) => {
                config.trust_cert();
                Ok(())
            }
            // The default: verify against the system trust store. Azure SQL
            // presents a publicly trusted certificate, so this is what the
            // common deployment wants and previously could not have.
            (None, false, false) => Ok(()),
        }
    }
}

/// Whether an ADO connection string points tiberius at a CA file.
///
/// Read here rather than inferred, because the consequence of getting it wrong
/// is a panic rather than a bad connection.
fn ado_names_ca(ado: Option<&str>) -> bool {
    ado.is_some_and(|ado| {
        ado.split(';').any(|pair| {
            pair.split_once('=').is_some_and(|(key, value)| {
                key.trim().eq_ignore_ascii_case("trustservercertificateca")
                    && !value.trim().is_empty()
            })
        })
    })
}

/// The scope a SQL Server access token has to be issued for.
///
/// Entra will happily issue a token for the wrong audience, and SQL Server will
/// reject it with a login failure that says nothing about the audience, so this
/// is not somewhere to accept a user-supplied value.
const SQL_SCOPE: &str = "https://database.windows.net/.default";
const SQL_RESOURCE: &str = "https://database.windows.net/";

/// How the profile wants a Microsoft Entra token obtained.
///
/// The connector already accepted a token someone else had minted. That is the
/// least useful form: an access token lives about an hour, so a saved
/// connection stops working overnight. These two acquire one at connect time.
#[derive(Debug, Clone, PartialEq, Eq)]
enum EntraCredential {
    /// A service principal's client id and secret.
    ClientSecret {
        tenant_id: String,
        client_id: String,
        client_secret: String,
    },
    /// The identity the host itself runs as, from the platform's token
    /// endpoint. `client_id` selects a user-assigned identity; without it the
    /// system-assigned one is used.
    ManagedIdentity { client_id: Option<String> },
}

impl EntraCredential {
    /// `None` when the profile asks for neither.
    ///
    /// `Err` when it asks for a service principal and leaves a part out, which
    /// is worth saying: the alternative is falling through to unauthenticated
    /// and reporting a login failure the user cannot explain.
    fn from_request(request: &Value) -> Result<Option<Self>, String> {
        if option_bool(request, &["managedIdentity", "useManagedIdentity", "msi"]) == Some(true) {
            return Ok(Some(Self::ManagedIdentity {
                client_id: option_string(
                    request,
                    &[
                        "managedIdentityClientId",
                        "userAssignedClientId",
                        "msiClientId",
                    ],
                ),
            }));
        }

        let tenant_id = option_string(request, &["tenantId", "azureTenantId", "tenant"]);
        let client_id = option_string(request, &["clientId", "azureClientId", "applicationId"]);
        let client_secret = option_string(
            request,
            &[
                "clientSecret",
                "azureClientSecret",
                "servicePrincipalSecret",
            ],
        );

        match (tenant_id, client_id, client_secret) {
            (None, None, None) => Ok(None),
            (Some(tenant_id), Some(client_id), Some(client_secret)) => {
                Ok(Some(Self::ClientSecret {
                    tenant_id,
                    client_id,
                    client_secret,
                }))
            }
            (tenant_id, client_id, client_secret) => {
                let mut missing = Vec::new();
                if tenant_id.is_none() {
                    missing.push("tenantId");
                }
                if client_id.is_none() {
                    missing.push("clientId");
                }
                if client_secret.is_none() {
                    missing.push("clientSecret");
                }
                Err(format!(
                    "Entra service principal authentication needs {} as well.",
                    missing.join(", ")
                ))
            }
        }
    }

    async fn fetch_token(&self, client: &HttpClient) -> Result<String, String> {
        match self {
            Self::ClientSecret {
                tenant_id,
                client_id,
                client_secret,
            } => {
                let url = format!(
                    "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
                    percent_encode(tenant_id)
                );
                let body = format!(
                    "grant_type=client_credentials&client_id={}&client_secret={}&scope={}",
                    percent_encode(client_id),
                    percent_encode(client_secret),
                    percent_encode(SQL_SCOPE)
                );
                let response = client
                    .post(url)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(body)
                    .send()
                    .await
                    .map_err(|err| format!("Entra token request failed: {err}"))?;
                read_token(response, "access_token", "Entra").await
            }
            Self::ManagedIdentity { client_id } => {
                let (url, header) = managed_identity_endpoint(client_id.as_deref());
                let mut request = client.get(url);
                for (name, value) in header {
                    request = request.header(name, value);
                }
                let response = request.send().await.map_err(|err| {
                    format!(
                        "the managed identity token request failed: {err}. This works only \
                         where a managed identity is available -- an Azure VM, App Service, \
                         Container App, or AKS pod."
                    )
                })?;
                read_token(response, "access_token", "the managed identity endpoint").await
            }
        }
    }
}

/// Where to ask for a managed identity token, and what to send with the ask.
///
/// Two shapes exist. App Service, Functions and Container Apps inject
/// `IDENTITY_ENDPOINT` and a secret in `IDENTITY_HEADER`; a plain VM or AKS
/// node has neither and answers on the IMDS link-local address instead. Trying
/// the injected one first is what every Azure SDK does, because on App Service
/// the IMDS address is not routable at all.
fn managed_identity_endpoint(client_id: Option<&str>) -> (String, Vec<(String, String)>) {
    managed_identity_endpoint_from(
        std::env::var("IDENTITY_ENDPOINT").ok().as_deref(),
        std::env::var("IDENTITY_HEADER").ok().as_deref(),
        client_id,
    )
}

/// The choice itself, with the environment passed in.
///
/// Kept pure so it can be tested without `set_var`: the environment is
/// process-global, so env-mutating tests race each other under the default
/// parallel runner and fail in a way that looks like a logic bug.
fn managed_identity_endpoint_from(
    identity_endpoint: Option<&str>,
    identity_header: Option<&str>,
    client_id: Option<&str>,
) -> (String, Vec<(String, String)>) {
    let user_assigned = client_id
        .map(|id| format!("&client_id={}", percent_encode(id)))
        .unwrap_or_default();

    // Both or neither: sending no header to the injected endpoint returns 401,
    // which reads as a permissions problem rather than a configuration one.
    if let (Some(endpoint), Some(secret)) = (identity_endpoint, identity_header) {
        let url = format!(
            "{endpoint}?api-version=2019-08-01&resource={}{user_assigned}",
            percent_encode(SQL_RESOURCE)
        );
        return (
            url,
            vec![("X-IDENTITY-HEADER".to_string(), secret.to_string())],
        );
    }

    let url = format!(
        "http://169.254.169.254/metadata/identity/oauth2/token\
         ?api-version=2018-02-01&resource={}{user_assigned}",
        percent_encode(SQL_RESOURCE)
    );
    (url, vec![("Metadata".to_string(), "true".to_string())])
}

/// Pull a token out of a token response.
///
/// The body is never quoted back: a failed Entra token response includes the
/// tenant and client id, and on some errors the assertion that was sent.
async fn read_token(response: reqwest::Response, field: &str, who: &str) -> Result<String, String> {
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|err| format!("{who} token response read failed: {err}"))?;
    if !status.is_success() {
        // The error *code* is safe and is the one thing that identifies the
        // problem, so it is worth digging out.
        let code = serde_json::from_str::<Value>(&text)
            .ok()
            .and_then(|value| {
                value
                    .get("error")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .map(|code| format!(" ({code})"))
            .unwrap_or_default();
        return Err(format!(
            "{who} returned HTTP {status}{code} for the token request."
        ));
    }
    serde_json::from_str::<Value>(&text)
        .ok()
        .and_then(|value| value.get(field).and_then(Value::as_str).map(str::to_string))
        .ok_or_else(|| format!("the {who} token response contained no {field}."))
}

impl SqlServerConfig {
    async fn from_request(request: &Value) -> Result<Self, String> {
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
        // A credential the profile configures is exchanged for a token here,
        // so the rest of the driver only ever sees an access token. An
        // explicitly supplied token wins: it is the more specific instruction.
        let access_token = match (&access_token, EntraCredential::from_request(request)?) {
            (None, Some(credential)) => Some(credential.fetch_token(&HttpClient::new()).await?),
            _ => access_token,
        };
        let tls = TlsTrust::from_request(request);
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
            tls,
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
        self.tls
            .apply(&mut config, ado_names_ca(self.ado.as_deref()))?;
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
        let config = block_on_config(&request).unwrap();
        assert_eq!(config.host, "db.example.test");
        assert_eq!(config.port, 1434);
        assert_eq!(config.database.as_deref(), Some("app"));
        assert_eq!(config.user.as_deref(), Some("sa"));
    }

    #[test]
    fn reads_an_entra_access_token_under_its_usual_names() {
        for field in ["accessToken", "aadToken", "azureAccessToken", "entraToken"] {
            let config = block_on_config(&json!({
                "profile": { "host": "sql.local", "options": { field: "eyJ0oken" } }
            }))
            .expect("config");
            assert_eq!(config.access_token.as_deref(), Some("eyJ0oken"), "{field}");
        }
    }

    #[test]
    fn a_sql_login_profile_carries_no_token() {
        let config = block_on_config(&json!({
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
        let config = block_on_config(&json!({
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
        let config = block_on_config(&json!({
            "profile": { "host": "sql.local", "user": "sa", "password": "pw" }
        }))
        .expect("config");
        assert_eq!(config.redact("login failed"), "login failed");
    }

    #[test]
    fn an_ado_string_is_still_replaced() {
        let config = block_on_config(&json!({
            "profile": { "options": { "connectionString": "Server=sql.local;User Id=sa;Password=pw" } }
        }))
        .expect("config");
        let redacted = config.redact("cannot open Server=sql.local;User Id=sa;Password=pw");
        assert!(redacted.contains("<sqlserver-connection>"), "{redacted}");
        assert!(!redacted.contains("Password=pw"), "{redacted}");
    }

    #[test]
    fn verification_is_on_unless_the_profile_turns_it_off() {
        // The connector used to call `trust_cert()` unconditionally, so every
        // connection accepted any certificate and no option could change it.
        let trust = TlsTrust::from_request(&json!({ "profile": { "host": "db.example" } }));
        assert!(!trust.accept_invalid_certs);
        assert_eq!(trust.ca_path, None);
        assert_eq!(trust.encryption, None);
    }

    #[test]
    fn the_insecure_option_is_spelled_the_same_as_in_every_other_connector() {
        for field in [
            "sslInsecure",
            "tlsInsecure",
            "trustServerCertificate",
            "acceptInvalidCerts",
        ] {
            let trust =
                TlsTrust::from_request(&json!({ "profile": { "options": { field: "true" } } }));
            assert!(trust.accept_invalid_certs, "{field}");
        }
    }

    #[test]
    fn a_certificate_authority_is_read_under_each_spelling() {
        for field in [
            "sslRootCert",
            "tlsCaCertificate",
            "caCertificate",
            "trustServerCertificateCa",
        ] {
            let trust = TlsTrust::from_request(&json!({
                "profile": { "options": { field: "/etc/ssl/private-ca.pem" } }
            }));
            assert_eq!(
                trust.ca_path.as_deref(),
                Some("/etc/ssl/private-ca.pem"),
                "{field}"
            );
        }
    }

    #[test]
    fn asking_for_both_a_ca_and_blanket_trust_is_refused_rather_than_guessed() {
        let trust = TlsTrust {
            ca_path: Some("/etc/ssl/ca.pem".into()),
            accept_invalid_certs: true,
            encryption: None,
        };
        let mut config = Config::new();
        let err = trust.apply(&mut config, false).unwrap_err();
        assert!(err.contains("Choose one"), "{err}");
    }

    #[test]
    fn a_connection_string_naming_a_ca_is_left_alone() {
        // This is the case that used to panic. tiberius makes `trust_cert` and
        // `trust_cert_ca` mutually exclusive and enforces it with `panic!`, and
        // `from_ado_string` sets the CA when the string carries
        // `TrustServerCertificateCA=` -- so the old unconditional
        // `trust_cert()` took the host down on exactly the careful profiles.
        let trust = TlsTrust::default();
        let mut config = Config::new();
        assert!(trust.apply(&mut config, true).is_ok());
    }

    #[test]
    fn a_connection_string_ca_plus_an_insecure_option_is_refused_not_panicked() {
        let trust = TlsTrust {
            ca_path: None,
            accept_invalid_certs: true,
            encryption: None,
        };
        let mut config = Config::new();
        let err = trust.apply(&mut config, true).unwrap_err();
        assert!(err.contains("Choose one"), "{err}");
    }

    #[test]
    fn a_missing_certificate_authority_file_is_reported_before_connecting() {
        let trust = TlsTrust {
            ca_path: Some("/nonexistent/ca.pem".into()),
            accept_invalid_certs: false,
            encryption: None,
        };
        let mut config = Config::new();
        let err = trust.apply(&mut config, false).unwrap_err();
        assert!(err.contains("/nonexistent/ca.pem"), "{err}");
        assert!(err.contains("does not exist"), "{err}");
    }

    #[test]
    fn ado_strings_are_scanned_for_a_named_certificate_authority() {
        assert!(ado_names_ca(Some(
            "Server=db;TrustServerCertificateCA=/etc/ssl/ca.pem;Database=app"
        )));
        assert!(ado_names_ca(Some(
            "Server=db;trustservercertificateca = /etc/ssl/ca.pem"
        )));
        assert!(!ado_names_ca(Some("Server=db;TrustServerCertificate=true")));
        assert!(!ado_names_ca(Some(
            "Server=db;TrustServerCertificateCA=;Database=app"
        )));
        assert!(!ado_names_ca(None));
    }

    #[test]
    fn encryption_levels_map_from_the_words_a_user_would_write() {
        let level = |value: &str| {
            TlsTrust::from_request(&json!({ "profile": { "options": { "encrypt": value } } }))
                .encryption
        };
        assert_eq!(level("required"), Some(EncryptionLevel::Required));
        assert_eq!(level("true"), Some(EncryptionLevel::Required));
        assert_eq!(level("prefer"), Some(EncryptionLevel::On));
        // tiberius spells "encrypt the login only" as `Off`; a user writing
        // `off` means no encryption, so the two must not be conflated.
        assert_eq!(level("off"), Some(EncryptionLevel::NotSupported));
        assert_eq!(level("loginOnly"), Some(EncryptionLevel::Off));
        assert_eq!(level("nonsense"), None);
    }

    #[test]
    fn a_real_ado_config_naming_a_ca_survives_the_trust_settings() {
        // The regression itself, and it was verified by restoring the old line
        // here: `from_ado_string` puts the config into
        // `TrustConfig::CaCertificateLocation`, and the old unconditional
        // `config.trust_cert()` then hit tiberius's own
        // `'trust_cert' and 'trust_cert_ca' are mutual exclusive!` panic. So
        // naming a private CA -- the careful configuration -- took the host
        // process down, while `TrustServerCertificate=true` worked fine.
        let ado = "Server=tcp:db.example,1433;Database=app;\
                   User Id=sa;Password=pw;TrustServerCertificateCA=/etc/ssl/ca.pem";
        let mut config = Config::from_ado_string(ado).expect("ado string");
        let trust = TlsTrust::from_request(&json!({ "profile": { "url": ado } }));
        assert!(
            trust.apply(&mut config, ado_names_ca(Some(ado))).is_ok(),
            "a connection string naming a CA must not be touched again"
        );
    }

    /// The config builder can perform a token exchange, so it is async; these
    /// tests only exercise paths that do not reach the network.
    fn block_on_config(request: &Value) -> Result<SqlServerConfig, String> {
        runtime()
            .expect("runtime")
            .block_on(SqlServerConfig::from_request(request))
    }

    #[test]
    fn a_profile_asking_for_neither_gets_none() {
        assert_eq!(
            EntraCredential::from_request(&json!({ "profile": {} })).unwrap(),
            None
        );
    }

    #[test]
    fn a_service_principal_is_recognised_under_each_spelling() {
        for (tenant, client, secret) in [
            ("tenantId", "clientId", "clientSecret"),
            ("azureTenantId", "azureClientId", "azureClientSecret"),
        ] {
            let credential = EntraCredential::from_request(&json!({
                "profile": { "options": {
                    tenant: "contoso.onmicrosoft.com",
                    client: "app-id",
                    secret: "shh"
                } }
            }))
            .unwrap()
            .expect("credential");
            assert_eq!(
                credential,
                EntraCredential::ClientSecret {
                    tenant_id: "contoso.onmicrosoft.com".into(),
                    client_id: "app-id".into(),
                    client_secret: "shh".into(),
                }
            );
        }
    }

    #[test]
    fn a_partial_service_principal_names_what_is_missing() {
        // The alternative is falling through to unauthenticated and reporting a
        // login failure the user has no way to connect to a typo.
        let err = EntraCredential::from_request(&json!({
            "profile": { "options": { "clientId": "app-id" } }
        }))
        .unwrap_err();
        assert!(err.contains("tenantId"), "{err}");
        assert!(err.contains("clientSecret"), "{err}");
        assert!(!err.contains("clientId,"), "{err}");
    }

    #[test]
    fn managed_identity_is_selected_by_the_flag_alone() {
        assert_eq!(
            EntraCredential::from_request(&json!({
                "profile": { "options": { "managedIdentity": true } }
            }))
            .unwrap(),
            Some(EntraCredential::ManagedIdentity { client_id: None })
        );
    }

    #[test]
    fn managed_identity_accepts_the_flag_as_a_string() {
        // A connection form submits "true", not a JSON boolean.
        assert_eq!(
            EntraCredential::from_request(&json!({
                "profile": { "options": { "useManagedIdentity": "true" } }
            }))
            .unwrap(),
            Some(EntraCredential::ManagedIdentity { client_id: None })
        );
    }

    #[test]
    fn a_user_assigned_identity_carries_its_client_id() {
        assert_eq!(
            EntraCredential::from_request(&json!({
                "profile": { "options": {
                    "managedIdentity": true,
                    "managedIdentityClientId": "11111111-2222-3333-4444-555555555555"
                } }
            }))
            .unwrap(),
            Some(EntraCredential::ManagedIdentity {
                client_id: Some("11111111-2222-3333-4444-555555555555".into())
            })
        );
    }

    #[test]
    fn managed_identity_wins_over_a_stale_service_principal() {
        // Both sets of fields can survive in a profile the user edited; the
        // explicit flag is the more recent intent.
        assert_eq!(
            EntraCredential::from_request(&json!({
                "profile": { "options": {
                    "managedIdentity": true,
                    "tenantId": "t", "clientId": "c", "clientSecret": "s"
                } }
            }))
            .unwrap(),
            Some(EntraCredential::ManagedIdentity { client_id: None })
        );
    }

    #[test]
    fn the_imds_endpoint_is_used_when_nothing_is_injected() {
        // Kept as a pure function of the environment so it can be tested
        // without `set_var`, which races under the parallel test runner.
        let (url, headers) = managed_identity_endpoint_from(None, None, None);
        assert!(url.starts_with("http://169.254.169.254/"), "{url}");
        assert!(
            url.contains("resource=https%3A%2F%2Fdatabase.windows.net%2F"),
            "{url}"
        );
        assert_eq!(headers, vec![("Metadata".to_string(), "true".to_string())]);
    }

    #[test]
    fn the_injected_endpoint_wins_where_the_platform_provides_one() {
        // On App Service the IMDS address is not routable at all, so preferring
        // the injected endpoint is not merely a nicety.
        let (url, headers) = managed_identity_endpoint_from(
            Some("http://127.0.0.1:42424/msi/token"),
            Some("secret-header"),
            None,
        );
        assert!(
            url.starts_with("http://127.0.0.1:42424/msi/token?"),
            "{url}"
        );
        assert!(url.contains("api-version=2019-08-01"), "{url}");
        assert_eq!(
            headers,
            vec![("X-IDENTITY-HEADER".to_string(), "secret-header".to_string())]
        );
    }

    #[test]
    fn a_user_assigned_client_id_is_encoded_into_the_query() {
        let (url, _) = managed_identity_endpoint_from(None, None, Some("app/id with space"));
        assert!(url.contains("&client_id=app%2Fid%20with%20space"), "{url}");
    }

    #[test]
    fn an_injected_endpoint_without_its_header_falls_back_to_imds() {
        // Half-configured is not configured: sending no header to the injected
        // endpoint returns 401, which reads as a permissions problem.
        let (url, _) =
            managed_identity_endpoint_from(Some("http://127.0.0.1:42424/msi/token"), None, None);
        assert!(url.starts_with("http://169.254.169.254/"), "{url}");
    }
}
