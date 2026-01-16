use dotenvy::dotenv;
use fulgurant::api_key::hash_api_key;
use fulgurant::users::generate_encryption_key;
use rand::Rng;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;
use time::{Duration, OffsetDateTime};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();
    println!("Seeding database with random users...");
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let options = SqliteConnectOptions::from_str(database_url.as_str())?
        .create_if_missing(true)
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect_with(options)
        .await?;
    let first_names = vec![
        "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank", "Grace", "Henry", "Iris", "Jack",
        "Kate", "Liam", "Maya", "Noah", "Olivia", "Paul", "Quinn", "Ruby", "Sam", "Tara", "Uma",
        "Victor", "Wendy", "Xavier", "Yara", "Zoe",
    ];
    let last_names = vec![
        "Anderson",
        "Brown",
        "Chen",
        "Davis",
        "Evans",
        "Foster",
        "Garcia",
        "Harris",
        "Ivanov",
        "Johnson",
        "Kim",
        "Lee",
        "Martinez",
        "Nguyen",
        "O'Brien",
        "Patel",
        "Quinn",
        "Rodriguez",
        "Smith",
        "Taylor",
        "Underwood",
        "Vargas",
        "Wilson",
        "Xu",
        "Young",
        "Zhang",
    ];
    let mut rng = rand::rng();
    let password = "Password123!"; // Default password for all seeded users
    let password_hash = hash_api_key(password)?;
    for i in 1..=10 {
        let first_name = first_names[rng.random_range(0..first_names.len())];
        let last_name = last_names[rng.random_range(0..last_names.len())];
        let random_num: u32 = rng.random_range(1000..9999);
        let email = format!(
            "{}.{}{}@example.com",
            first_name.to_lowercase(),
            last_name.to_lowercase(),
            random_num
        );
        let encryption_key = generate_encryption_key();
        let email_verified = rng.random_bool(0.7); // 70% chance of being verified
        let role = if rng.random_bool(0.2) {
            "Admin"
        } else {
            "User"
        }; // 20% chance of being admin
        let days_ago: i64 = rng.random_range(0..30);
        let last_activity = OffsetDateTime::now_utc() - Duration::days(days_ago);
        let shares = rng.random_range(0..51);
        match sqlx::query(
            "INSERT INTO users (email, first_name, last_name, password_hash, encryption_key, email_verified, role, last_activity, shares) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
        .bind(&email)
        .bind(first_name)
        .bind(last_name)
        .bind(&password_hash)
        .bind(&encryption_key)
        .bind(email_verified)
        .bind(role)
        .bind(last_activity)
        .bind(shares)
        .execute(&pool)
        .await
        {
            Ok(_) => {
                let verified_status = if email_verified { "verified" } else { "unverified" };
                print!("✓ Created {} user #{}: {} {} ({})", verified_status, i, first_name, last_name, email);
                if role == "Admin" {
                    print!(" [Admin]");
                }
                println!();
            }
            Err(e) => {
                eprintln!("✗ Failed to create user {}: {}", email, e);
            }
        }
    }
    println!("Seeding complete! Created 10 random users.");
    println!("All users have password: {}", password);

    Ok(())
}
