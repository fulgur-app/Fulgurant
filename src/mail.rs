use lettre::{
    Address, Message, SmtpTransport, Transport,
    message::{Mailbox, MultiPart, SinglePart, header},
    transport::smtp::authentication::Credentials,
};

#[derive(Clone)]
pub struct Mailer {
    smtp_host: String,
    #[allow(dead_code)]
    smtp_port: u16,
    smtp_user: String,
    smtp_password: String,
}

impl Mailer {
    /// Creates a new Mailer
    ///
    /// ### Returns
    /// - `Mailer`: The Mailer
    pub fn new() -> Self {
        let smtp_host = std::env::var("SMTP_HOST").expect("SMTP_HOST must be set");
        let smtp_port = std::env::var("SMTP_PORT")
            .expect("SMTP_PORT must be set")
            .parse()
            .expect("SMTP_PORT must be a number");
        let smtp_user = std::env::var("SMTP_LOGIN").expect("SMTP_LOGIN must be set");
        let smtp_password = std::env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");
        Self {
            smtp_host,
            smtp_port,
            smtp_user,
            smtp_password,
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
        let mailer = SmtpTransport::starttls_relay(&self.smtp_host)?;
        let mailer = mailer.credentials(Credentials::new(
            self.smtp_user.clone(),
            self.smtp_password.clone(),
        ));
        let mailer = mailer.build();
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

        let _ = match mailer.send(&email) {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::error!("Failed to send email: {}", e);
                Err(anyhow::anyhow!("Failed to send email: {}", e))
            }
        };
        Ok(())
    }
}
