use super::*;
#[derive(Serialize)]
pub struct AccountStatus {
    initialized: bool,
    salt: Option<String>,
}
#[derive(Deserialize)]
pub struct Setup {
    username: String,
    salt: String,
    auth: String,
    envelope: String,
}
#[derive(Deserialize)]
pub struct Login {
    username: String,
    auth: String,
    name: String,
}
#[derive(Serialize)]
pub struct Session {
    token: String,
    envelope: String,
}
fn hex_len(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn user_ok(s: &str) -> bool {
    (3..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}
pub async fn status(State(s): State<App>) -> Result<Json<AccountStatus>> {
    let db = s.db.lock().map_err(internal)?;
    let salt = db
        .query_row("SELECT salt FROM owner_account WHERE id=1", [], |r| {
            r.get::<_, String>(0)
        })
        .optional()
        .map_err(internal)?;
    Ok(Json(AccountStatus {
        initialized: salt.is_some(),
        salt,
    }))
}
pub async fn setup(State(s): State<App>, Json(r): Json<Setup>) -> Result<StatusCode> {
    if std::env::var("SYNC_ENABLE_OWNER_SETUP").as_deref() != Ok("1") {
        return Err((StatusCode::FORBIDDEN, "owner setup disabled"));
    }
    if !user_ok(&r.username)
        || !valid_hash(&r.salt)
        || !valid_hash(&r.auth)
        || !hex_len(&r.envelope, 120)
    {
        return Err(bad("invalid account setup"));
    }
    let mut db = s.db.lock().map_err(internal)?;
    let tx = db.transaction().map_err(internal)?;
    let occupied:i64=tx.query_row("SELECT (SELECT count(*) FROM owner_account)+(SELECT count(*) FROM files)+(SELECT count(*) FROM devices)+(SELECT count(*) FROM versions)",[],|r|r.get(0)).map_err(internal)?;
    if occupied != 0 {
        return Err((
            StatusCode::CONFLICT,
            "account already initialized or vault not empty",
        ));
    }
    tx.execute(
        "INSERT INTO owner_account VALUES (1,?,?,?,?)",
        params![r.username, r.salt, hash(r.auth.as_bytes()), r.envelope],
    )
    .map_err(internal)?;
    tx.execute("DELETE FROM pairs", []).map_err(internal)?;
    tx.commit().map_err(internal)?;
    Ok(StatusCode::CREATED)
}
pub async fn login(State(s): State<App>, Json(r): Json<Login>) -> Result<Json<Session>> {
    {
        let mut budget = s.enrollment_budget.lock().map_err(internal)?;
        if budget.0.elapsed() >= std::time::Duration::from_secs(60) {
            *budget = (std::time::Instant::now(), 0);
        }
        if budget.1 >= 60 {
            return Err((StatusCode::TOO_MANY_REQUESTS, "login rate limit"));
        }
        budget.1 += 1;
    }
    if !user_ok(&r.username)
        || !valid_hash(&r.auth)
        || r.name.trim().is_empty()
        || r.name.len() > 100
    {
        return Err(bad("invalid login"));
    }
    let mut db = s.db.lock().map_err(internal)?;
    let tx = db.transaction().map_err(internal)?;
    let envelope = tx
        .query_row(
            "SELECT envelope FROM owner_account WHERE id=1 AND username=? AND auth_hash=?",
            params![r.username, hash(r.auth.as_bytes())],
            |r| r.get::<_, String>(0),
        )
        .optional()
        .map_err(internal)?
        .ok_or((StatusCode::UNAUTHORIZED, "invalid credentials"))?;
    let count: i64 = tx
        .query_row("SELECT count(*) FROM devices", [], |r| r.get(0))
        .map_err(internal)?;
    if count >= 32 {
        return Err((StatusCode::TOO_MANY_REQUESTS, "device limit reached"));
    }
    let token = secret();
    tx.execute(
        "INSERT INTO devices(name,token_hash,created) VALUES(?,?,?)",
        params![r.name, hash(token.as_bytes()), now()],
    )
    .map_err(internal)?;
    tx.commit().map_err(internal)?;
    Ok(Json(Session { token, envelope }))
}
