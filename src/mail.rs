use lettre::{
    Address, Message, SmtpTransport, Transport,
    message::{Mailbox, MultiPart, SinglePart, header},
    transport::smtp::authentication::Credentials,
};

pub struct Mailer {
    smtp_user: String,
    transport: Option<SmtpTransport>,
}

impl Mailer {
    /// Creates a new Mailer
    ///
    /// ### Arguments
    /// - `is_prod`: If true, requires SMTP env vars and creates transport. If false, transport is None (emails logged).
    ///
    /// ### Returns
    /// - `Ok(Mailer)`: The Mailer with optional transport
    /// - `Err(anyhow::Error)`: Configuration error while initializing SMTP transport
    pub fn new(is_prod: bool) -> Result<Self, anyhow::Error> {
        if is_prod {
            let smtp_host = std::env::var("SMTP_HOST")
                .map_err(|_| anyhow::anyhow!("SMTP_HOST must be set in production mode"))?;
            let smtp_user = std::env::var("SMTP_LOGIN")
                .map_err(|_| anyhow::anyhow!("SMTP_LOGIN must be set in production mode"))?;
            let smtp_password = std::env::var("SMTP_PASSWORD")
                .map_err(|_| anyhow::anyhow!("SMTP_PASSWORD must be set in production mode"))?;
            let smtp_port = std::env::var("SMTP_PORT")
                .unwrap_or_else(|_| "587".to_string())
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("SMTP_PORT must be a valid integer"))?;
            if smtp_port == 0 {
                return Err(anyhow::anyhow!("SMTP_PORT must be in range 1-65535"));
            }
            let transport = SmtpTransport::starttls_relay(&smtp_host)
                .map_err(|e| anyhow::anyhow!("Failed to create SMTP transport: {}", e))?
                .port(smtp_port)
                .credentials(Credentials::new(smtp_user.clone(), smtp_password))
                .build();

            Ok(Self {
                smtp_user,
                transport: Some(transport),
            })
        } else {
            tracing::debug!(
                "Development mode: Mailer created without SMTP transport (emails will be logged)"
            );
            Ok(Self {
                smtp_user: String::from("dev@example.com"),
                transport: None,
            })
        }
    }

    /// Sends a verification email
    ///
    /// ### Arguments
    /// - `to`: The email address to send the email to
    /// - `verification_code`: The verification code to send
    ///
    /// ### Returns
    /// - `Ok(())`: The email was sent successfully
    /// - `Err(anyhow::Error)`: The error that occurred while sending the email
    pub async fn send_verification_email(
        &self,
        to: String,
        verification_code: String,
    ) -> Result<(), anyhow::Error> {
        let html_body = format!(
            r#"<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Hello from Fulgur!</title>
            </head>
            <body>
                <div style="display: flex; flex-direction: column; align-items: center;">
                    <h2 style="font-family: Arial, Helvetica, sans-serif;">Your Fulgur verification code is:</h2>
                    <h4 style="font-family: Arial, Helvetica, sans-serif;">{}</h4>
                </div>
            </body>
            </html>"#,
            verification_code
        );
        let text_body = format!(
            "Hello from Fulgur!\n\nYour verification code is: {}",
            verification_code
        );
        let subject = "Your Fulgur Verification Code".to_string();
        self.send_email(to, subject, text_body.to_string(), html_body.to_string())
            .await
    }

    /// Sends an email
    ///
    /// ### Arguments
    /// - `to`: The email address to send the email to
    /// - `subject`: The subject of the email
    /// - `text_body`: The text body of the email
    /// - `html_body`: The HTML body of the email
    ///
    /// ### Returns
    /// - `Ok(())`: The result of the operation if the email was sent successfully
    /// - `Err(anyhow::Error)`: The error that occurred while sending the email
    pub async fn send_email(
        &self,
        to: String,
        subject: String,
        text_body: String,
        html_body: String,
    ) -> Result<(), anyhow::Error> {
        let transport = self
            .transport
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SMTP transport not configured (development mode)"))?;

        let email = Message::builder()
            .from(Mailbox::new(
                None,
                self.smtp_user.clone().parse::<Address>()?,
            ))
            .to(Mailbox::new(None, to.parse::<Address>()?))
            .subject(subject)
            .multipart(
                MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_PLAIN)
                            .body(text_body),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(header::ContentType::TEXT_HTML)
                            .body(html_body),
                    ),
            )?;

        transport.send(&email).map_err(|e| {
            tracing::error!("Failed to send email: {}", e);
            anyhow::anyhow!("Failed to send email: {}", e)
        })?;
        Ok(())
    }
}
