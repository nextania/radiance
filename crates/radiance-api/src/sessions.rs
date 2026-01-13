use std::time::{SystemTime, UNIX_EPOCH};

use mongodb::{Collection, bson::doc};
use once_cell::sync::OnceCell;
use mongodb::{Client, Database};
use rand::{Rng, distr::Alphanumeric};
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use crate::environment::{MONGODB_DATABASE, MONGODB_URI};

static DATABASE: OnceCell<Client> = OnceCell::new();
static COLLECTION: OnceCell<Collection<Session>> = OnceCell::new();

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: String,
    pub token: String,
    pub expires_at: u64,
    pub oidc_data: Option<OidcSessionData>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcSessionData {
    pub provider: String,
    pub subject: String,
    pub sid: Option<String>,
}

pub fn get_time_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Unexpected error: time went backwards")
        .as_millis() as u64
}

impl Session {
    pub async fn delete(&self) -> mongodb::error::Result<()> {
        let collection = get_collection();
        collection.delete_one(doc! { "id": &self.id }).await?;
        Ok(())
    }

    pub async fn delete_oidc(provider: &str, subject: &str, sid: &Option<String>) -> mongodb::error::Result<()> {
        let collection = get_collection();
        let mut query = doc! { 
            "oidc_data.provider": provider,
            "oidc_data.subject": subject,
        };
        if let Some(sid) = sid {
            query.insert("oidc_data.sid", sid);
        }
        collection.delete_many(query).await?;
        Ok(())
    }

    pub async fn validate(token: &str) -> mongodb::error::Result<Option<Session>> {    
        let collection = get_collection();
        let query = collection
            .find_one(doc! {
                "token": token
            })
            .await?;
        if let Some(token_data) = query {
            let millis = get_time_millis();
            if millis > token_data.expires_at {
                collection.delete_one(doc! { "id": &token_data.id }).await?;
                return Ok(None);
            }
            return Ok(Some(token_data));
        }
        Ok(None)
    }

    pub async fn create(oidc: Option<OidcSessionData>) -> mongodb::error::Result<Session> {
        let token: String = rand::rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        let expires_at = get_time_millis() + 24 * 60 * 60 * 1000; // 24 hours
        let session = Session {
            id: Ulid::new().to_string(),
            token,
            expires_at,
            oidc_data: oidc,
        };
        let collection = get_collection();
        collection.insert_one(&session).await?;
        Ok(session)
    }
}

pub fn get_collection() -> &'static Collection<Session> {
    COLLECTION.get_or_init(|| get_database().collection::<Session>("sessions"))
}

pub async fn connect() {
    let client = Client::with_uri_str(&*MONGODB_URI)
        .await
        .expect("Failed to connect to MongoDB");
    DATABASE.set(client).expect("Failed to set MongoDB client");
}

pub fn get_database() -> Database {
    DATABASE.get().expect("Failed to get MongoDB client").database(&MONGODB_DATABASE)
}
