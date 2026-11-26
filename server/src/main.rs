use axum::{
    body::Bytes,
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        DefaultBodyLimit, Path, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use rand::{rngs::OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

const CHUNK: usize = 1024 * 1024;
const MAX_FILE: u64 = 512 * 1024 * 1024;
type Err = (StatusCode, &'static str);
type Result<T> = std::result::Result<T, Err>;
fn internal<T>(_: T) -> Err {
    (StatusCode::INTERNAL_SERVER_ERROR, "storage error")
}
fn bad(s: &'static str) -> Err {
    (StatusCode::BAD_REQUEST, s)
}
fn hash(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}
fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn secret() -> String {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 4096
        && p.split('/').all(|s| {
            !s.is_empty()
                && s != "."
                && s != ".."
                && !s.ends_with('.')
                && !s.ends_with(' ')
                && !s
                    .chars()
                    .any(|c| c.is_control() || "\\:*?\"<>|".contains(c))
                && !matches!(
                    s.to_ascii_lowercase().as_str(),
                    ".obsidian" | ".trash" | ".git"
                )
        })
}
#[derive(Clone)]
struct App {
    db: Arc<Mutex<Connection>>,
    blobs: PathBuf,
    changes: tokio::sync::broadcast::Sender<()>,
    sockets: Arc<tokio::sync::Semaphore>,
    storage: Arc<Mutex<u64>>,
    quota: u64,
    requests: Arc<tokio::sync::Semaphore>,
}
impl App {
    fn open(dir: PathBuf) -> std::result::Result<Self, Box<dyn std::error::Error>> {
        fs::create_dir_all(dir.join("blobs"))?;
        let db = Connection::open(dir.join("meta.sqlite"))?;
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
          CREATE TABLE IF NOT EXISTS devices (id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT UNIQUE NOT NULL, created INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS pairs (code_hash TEXT PRIMARY KEY, expires INTEGER NOT NULL);
          CREATE TABLE IF NOT EXISTS files (path TEXT PRIMARY KEY, rev INTEGER NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, chunks TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS versions (path TEXT NOT NULL, rev INTEGER NOT NULL, hash TEXT NOT NULL, size INTEGER NOT NULL, chunks TEXT NOT NULL, archived INTEGER NOT NULL, PRIMARY KEY(path,rev));")?;
        let has_deleted = {
            let mut q = db.prepare("PRAGMA table_info(files)")?;
            let names = q
                .query_map([], |r| r.get::<_, String>(1))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            names.iter().any(|n| n == "deleted")
        };
        if !has_deleted {
            db.execute(
                "ALTER TABLE files ADD COLUMN deleted INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        let used = fs::read_dir(dir.join("blobs"))?.try_fold(
            0u64,
            |total, entry| -> std::io::Result<u64> {
                let m = entry?.metadata()?;
                Ok(total.saturating_add(if m.is_file() { m.len() } else { 0 }))
            },
        )?;
        let quota = std::env::var("SYNC_QUOTA_BYTES")
            .ok()
            .map(|v| v.parse::<u64>())
            .transpose()?
            .unwrap_or(8 * 1024 * 1024 * 1024);
        Ok(Self {
            db: Arc::new(Mutex::new(db)),
            blobs: dir.join("blobs"),
            changes: tokio::sync::broadcast::channel(128).0,
            sockets: Arc::new(tokio::sync::Semaphore::new(32)),
            storage: Arc::new(Mutex::new(used)),
            quota,
            requests: Arc::new(tokio::sync::Semaphore::new(24)),
        })
    }
    fn pair(&self) -> Result<String> {
        let code = secret();
        let db = self.db.lock().map_err(internal)?;
        db.execute("DELETE FROM pairs WHERE expires < ?", [now()])
            .map_err(internal)?;
        db.execute(
            "INSERT INTO pairs VALUES (?,?)",
            params![hash(code.as_bytes()), now() + 600],
        )
        .map_err(internal)?;
        Ok(code)
    }
    fn auth(&self, headers: &HeaderMap) -> Result<i64> {
        let token = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .filter(|s| valid_hash(s))
            .ok_or((StatusCode::UNAUTHORIZED, "unauthorized"))?;
        let db = self.db.lock().map_err(internal)?;
        let found = db
            .query_row(
                "SELECT id FROM devices WHERE token_hash=?",
                [hash(token.as_bytes())],
                |r| r.get::<_, i64>(0),
            )
            .optional()
            .map_err(internal)?;
        found.ok_or((StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}
#[derive(Deserialize)]
struct Redeem {
    code: String,
    name: String,
}
#[derive(Serialize)]
struct Token {
    token: String,
}
async fn redeem(State(s): State<App>, Json(r): Json<Redeem>) -> Result<Json<Token>> {
    if !valid_hash(&r.code) || r.name.trim().is_empty() || r.name.len() > 100 {
        return Err(bad("invalid enrollment"));
    }
    let mut db = s.db.lock().map_err(internal)?;
    let tx = db.transaction().map_err(internal)?;
    let consumed = tx
        .execute(
            "DELETE FROM pairs WHERE code_hash=? AND expires>=?",
            params![hash(r.code.as_bytes()), now()],
        )
        .map_err(internal)?;
    if consumed != 1 {
        return Err((StatusCode::UNAUTHORIZED, "expired or used code"));
    }
    let token = secret();
    tx.execute(
        "INSERT INTO devices(name,token_hash,created) VALUES(?,?,?)",
        params![r.name, hash(token.as_bytes()), now()],
    )
    .map_err(internal)?;
    tx.commit().map_err(internal)?;
    Ok(Json(Token { token }))
}
#[derive(Serialize)]
struct Pair {
    code: String,
    expires_in: u32,
}
async fn pair(State(s): State<App>, h: HeaderMap) -> Result<Json<Pair>> {
    s.auth(&h)?;
    Ok(Json(Pair {
        code: s.pair()?,
        expires_in: 600,
    }))
}
#[derive(Serialize, Deserialize, Clone)]
struct File {
    path: String,
    rev: i64,
    hash: String,
    size: u64,
    chunks: Vec<String>,
    deleted: bool,
}
fn row_file(row: &rusqlite::Row<'_>) -> rusqlite::Result<File> {
    let c: String = row.get(4)?;
    let chunks = serde_json::from_str(&c).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(4, rusqlite::types::Type::Text, Box::new(e))
    })?;
    Ok(File {
        path: row.get(0)?,
        rev: row.get(1)?,
        hash: row.get(2)?,
        size: row.get(3)?,
        chunks,
        deleted: row.get(5)?,
    })
}
async fn index(State(s): State<App>, h: HeaderMap) -> Result<Json<Vec<File>>> {
    s.auth(&h)?;
    let db = s.db.lock().map_err(internal)?;
    let mut q = db
        .prepare("SELECT path,rev,hash,size,chunks,deleted FROM files ORDER BY path")
        .map_err(internal)?;
    let rows = q
        .query_map([], row_file)
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(Json(rows))
}
#[derive(Deserialize)]
struct Missing {
    hashes: Vec<String>,
}
async fn missing(
    State(s): State<App>,
    h: HeaderMap,
    Json(r): Json<Missing>,
) -> Result<Json<Vec<String>>> {
    s.auth(&h)?;
    if r.hashes.len() > 4096 || r.hashes.iter().any(|v| !valid_hash(v)) {
        return Err(bad("invalid chunks"));
    }
    Ok(Json(
        r.hashes
            .into_iter()
            .filter(|v| !s.blobs.join(v).is_file())
            .collect(),
    ))
}
async fn upload(
    State(s): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    b: Bytes,
) -> Result<StatusCode> {
    s.auth(&h)?;
    if !valid_hash(&id) || b.is_empty() || b.len() > CHUNK || hash(&b) != id {
        return Err(bad("invalid chunk or checksum"));
    }
    let blobs = s.blobs.clone();
    let storage = s.storage.clone();
    let quota = s.quota;
    tokio::task::spawn_blocking(move || -> Result<()> {
        let mut used = storage.lock().map_err(internal)?;
        let target = blobs.join(id);
        if target.is_file() {
            return Ok(());
        }
        if used.saturating_add(b.len() as u64) > quota {
            return Err((StatusCode::INSUFFICIENT_STORAGE, "storage quota reached"));
        }
        let mut tmp = tempfile::NamedTempFile::new_in(&blobs).map_err(internal)?;
        tmp.write_all(&b).map_err(internal)?;
        tmp.as_file().sync_all().map_err(internal)?;
        match tmp.persist_noclobber(&target) {
            Ok(_) => {
                *used += b.len() as u64;
                Ok(())
            }
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(internal(e)),
        }
    })
    .await
    .map_err(internal)??;
    Ok(StatusCode::CREATED)
}
async fn download(State(s): State<App>, Path(id): Path<String>, h: HeaderMap) -> Result<Response> {
    s.auth(&h)?;
    if !valid_hash(&id) {
        return Err(bad("invalid hash"));
    }
    let b = tokio::fs::read(s.blobs.join(id))
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "chunk not found"))?;
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
        b,
    )
        .into_response())
}
#[derive(Deserialize)]
struct Commit {
    path: String,
    base_rev: i64,
    hash: String,
    size: u64,
    chunks: Vec<String>,
}
async fn commit(State(s): State<App>, h: HeaderMap, Json(c): Json<Commit>) -> Result<Json<File>> {
    s.auth(&h)?;
    if !valid_path(&c.path)
        || c.base_rev < 0
        || !valid_hash(&c.hash)
        || c.size > MAX_FILE
        || c.chunks.len() as u64 != c.size.div_ceil(CHUNK as u64)
        || c.chunks.iter().any(|v| !valid_hash(v))
    {
        return Err(bad("invalid file metadata"));
    }
    tokio::task::spawn_blocking(move||->Result<Json<File>>{
        let mut sha=Sha256::new(); let mut total=0u64;
        for (i,id) in c.chunks.iter().enumerate(){
            let b=fs::read(s.blobs.join(id)).map_err(|_|(StatusCode::CONFLICT,"missing chunk"))?;
            let expected=if i+1==c.chunks.len(){(c.size-total) as usize}else{CHUNK};
            if b.len()!=expected||hash(&b)!=*id{return Err(bad("chunk integrity error"));}
            total+=b.len() as u64; sha.update(&b);
        }
        if total!=c.size||hex::encode(sha.finalize())!=c.hash{return Err(bad("file integrity error"));}
        let mut db=s.db.lock().map_err(internal)?;
        let tx=db.transaction().map_err(internal)?;
        let old=tx.query_row("SELECT path,rev,hash,size,chunks,deleted FROM files WHERE path=?",[&c.path],row_file).optional().map_err(internal)?;
        if let Some(ref f)=old {if !f.deleted && f.hash==c.hash{return Ok(Json(f.clone()));}}
        if old.as_ref().map(|v|v.rev).unwrap_or(0)!=c.base_rev{return Err((StatusCode::CONFLICT,"revision changed"));}
        if let Some(f)=old.filter(|f|!f.deleted) {
            tx.execute("INSERT INTO versions VALUES (?,?,?,?,?,?)",params![f.path,f.rev,f.hash,f.size,serde_json::to_string(&f.chunks).map_err(internal)?,now()]).map_err(internal)?;
        }
        let f=File{path:c.path,rev:c.base_rev+1,hash:c.hash,size:c.size,chunks:c.chunks,deleted:false};
        tx.execute("INSERT INTO files(path,rev,hash,size,chunks,deleted) VALUES (?,?,?,?,?,0) ON CONFLICT(path) DO UPDATE SET rev=excluded.rev,hash=excluded.hash,size=excluded.size,chunks=excluded.chunks,deleted=0",params![f.path,f.rev,f.hash,f.size,serde_json::to_string(&f.chunks).map_err(internal)?]).map_err(internal)?;
        tx.commit().map_err(internal)?;
        let _=s.changes.send(());
        Ok(Json(f))
    }).await.map_err(internal)?
}
#[derive(Deserialize)]
struct DeleteFile {
    path: String,
    base_rev: i64,
}
async fn delete_file(
    State(s): State<App>,
    h: HeaderMap,
    Json(c): Json<DeleteFile>,
) -> Result<Json<File>> {
    s.auth(&h)?;
    if !valid_path(&c.path) || c.base_rev < 1 {
        return Err(bad("invalid deletion"));
    }
    let mut db = s.db.lock().map_err(internal)?;
    let tx = db.transaction().map_err(internal)?;
    let old = tx
        .query_row(
            "SELECT path,rev,hash,size,chunks,deleted FROM files WHERE path=?",
            [&c.path],
            row_file,
        )
        .optional()
        .map_err(internal)?
        .ok_or((StatusCode::NOT_FOUND, "file not found"))?;
    if old.deleted && old.rev == c.base_rev + 1 {
        return Ok(Json(old));
    }
    if old.rev != c.base_rev || old.deleted {
        return Err((StatusCode::CONFLICT, "revision changed"));
    }
    tx.execute(
        "INSERT INTO versions VALUES (?,?,?,?,?,?)",
        params![
            old.path,
            old.rev,
            old.hash,
            old.size,
            serde_json::to_string(&old.chunks).map_err(internal)?,
            now()
        ],
    )
    .map_err(internal)?;
    tx.execute(
        "UPDATE files SET rev=rev+1,deleted=1 WHERE path=?",
        [&c.path],
    )
    .map_err(internal)?;
    tx.commit().map_err(internal)?;
    let _ = s.changes.send(());
    Ok(Json(File {
        rev: old.rev + 1,
        deleted: true,
        ..old
    }))
}
#[derive(Deserialize)]
struct HistoryQuery {
    path: String,
}
async fn history(
    State(s): State<App>,
    h: HeaderMap,
    Json(c): Json<HistoryQuery>,
) -> Result<Json<Vec<File>>> {
    s.auth(&h)?;
    if !valid_path(&c.path) {
        return Err(bad("invalid path"));
    }
    let db = s.db.lock().map_err(internal)?;
    let mut q=db.prepare("SELECT path,rev,hash,size,chunks,0 FROM versions WHERE path=? ORDER BY rev DESC LIMIT 100").map_err(internal)?;
    let rows = q
        .query_map([c.path], row_file)
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(Json(rows))
}
#[derive(Serialize)]
struct Device {
    id: i64,
    name: String,
    created: i64,
    current: bool,
}
async fn devices(State(s): State<App>, h: HeaderMap) -> Result<Json<Vec<Device>>> {
    let me = s.auth(&h)?;
    let db = s.db.lock().map_err(internal)?;
    let mut q = db
        .prepare("SELECT id,name,created FROM devices ORDER BY id")
        .map_err(internal)?;
    let rows = q
        .query_map([], |r| {
            let id = r.get(0)?;
            Ok(Device {
                id,
                name: r.get(1)?,
                created: r.get(2)?,
                current: id == me,
            })
        })
        .map_err(internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(internal)?;
    Ok(Json(rows))
}
async fn revoke(State(s): State<App>, Path(id): Path<i64>, h: HeaderMap) -> Result<StatusCode> {
    let me = s.auth(&h)?;
    if me == id {
        return Err(bad("cannot revoke current device"));
    }
    let mut db = s.db.lock().map_err(internal)?;
    let tx = db.transaction().map_err(internal)?;
    let n = tx
        .execute("DELETE FROM devices WHERE id=?", [id])
        .map_err(internal)?;
    if n == 0 {
        return Err((StatusCode::NOT_FOUND, "device not found"));
    }
    tx.execute("DELETE FROM pairs", []).map_err(internal)?;
    tx.commit().map_err(internal)?;
    let _ = s.changes.send(());
    Ok(StatusCode::NO_CONTENT)
}
async fn watch(State(s): State<App>, ws: WebSocketUpgrade) -> Result<Response> {
    let permit = s
        .sockets
        .clone()
        .try_acquire_owned()
        .map_err(|_| (StatusCode::TOO_MANY_REQUESTS, "too many connections"))?;
    Ok(ws
        .max_message_size(256)
        .max_frame_size(256)
        .on_upgrade(move |socket| async move {
            let _permit = permit;
            watch_socket(s, socket).await;
        }))
}
async fn watch_socket(s: App, mut socket: WebSocket) {
    let first = tokio::time::timeout(std::time::Duration::from_secs(5), socket.recv()).await;
    let Ok(Some(Ok(Message::Text(token)))) = first else {
        return;
    };
    if !valid_hash(token.as_str()) {
        return;
    }
    let mut h = HeaderMap::new();
    let Ok(auth) = format!("Bearer {}", token).parse() else {
        return;
    };
    h.insert("authorization", auth);
    if s.auth(&h).is_err() {
        return;
    }
    let mut rx = s.changes.subscribe();
    if socket.send(Message::Text("ready".into())).await.is_err() {
        return;
    }
    let mut timer = tokio::time::interval(std::time::Duration::from_secs(20));
    timer.tick().await;
    loop {
        let event = tokio::select! {
            changed=rx.recv()=>match changed {Ok(())|Err(tokio::sync::broadcast::error::RecvError::Lagged(_))=>Some(Message::Text("changed".into())),_=>break},
            _=timer.tick()=>Some(Message::Ping(Vec::new().into())),
            msg=socket.recv()=>match msg {Some(Ok(Message::Pong(_)))|Some(Ok(Message::Ping(_)))=>None,_=>break},
        };
        if s.auth(&h).is_err() {
            break;
        }
        if let Some(event) = event {
            if tokio::time::timeout(std::time::Duration::from_secs(5), socket.send(event))
                .await
                .is_err()
            {
                break;
            }
        }
    }
}
#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::var_os("SYNC_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data"));
    let app = App::open(dir)?;
    if std::env::args().nth(1).as_deref() == Some("pair") {
        println!("{}", app.pair().map_err(|e| e.1)?);
        return Ok(());
    }
    let addr = std::env::var("SYNC_BIND").unwrap_or_else(|_| "127.0.0.1:8877".into());
    let router = Router::new()
        .route("/v1/health", get(|| async { "ok" }))
        .route("/v1/redeem", post(redeem))
        .route("/v1/pair", post(pair))
        .route("/v1/index", get(index))
        .route("/v1/missing", post(missing))
        .route("/v1/chunks/{id}", put(upload).get(download))
        .route("/v1/commit", post(commit))
        .route("/v1/delete", post(delete_file))
        .route("/v1/history", post(history))
        .route("/v1/devices", get(devices))
        .route("/v1/devices/{id}", axum::routing::delete(revoke))
        .route("/v1/watch", get(watch))
        .layer(DefaultBodyLimit::max(2 * CHUNK))
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            limit_requests,
        ))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("Listening on {}", addr);
    axum::serve(listener, router).await?;
    Ok(())
}
async fn limit_requests(
    State(s): State<App>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let Ok(_permit) = s.requests.clone().try_acquire_owned() else {
        return (StatusCode::TOO_MANY_REQUESTS, "too many requests").into_response();
    };
    match tokio::time::timeout(std::time::Duration::from_secs(90), next.run(req)).await {
        Ok(r) => r,
        Err(_) => (StatusCode::REQUEST_TIMEOUT, "request timed out").into_response(),
    }
}
