use std::collections::HashMap;
use std::sync::Arc;

use zbus::zvariant::OwnedObjectPath;

use keyring_core::Entry;
use keyring_core::api::{Credential, CredentialApi};
use keyring_core::error::{Error, Result};

use crate::service::{BINARY, Service, TEXT};

/// The specifier for an item in the secret-service.
///
/// The label, target and content types are captured from the modifiers
/// used when the specifier was created, so they are
/// available when a matching item needs to be created or set.
pub struct Specifier {
    ss: Arc<Service<'static>>,
    /// The label given to an item created for the entry.
    pub label: String,
    /// The collection the item is created in, or `None` for the default collection.
    pub target: Option<String>,
    /// The service of the entry.
    pub service: String,
    /// The user of the entry.
    pub user: String,
    /// The content type of a secret set as a password, `text/plain` unless
    /// given by the `password-content-type` modifier.
    pub password_content_type: String,
    /// The content type of a secret set as bytes, `application/octet-stream`
    /// unless given by the `secret-content-type` modifier.
    pub secret_content_type: String,
}

impl std::fmt::Debug for Specifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Specifier")
            .field("label", &self.label)
            .field("target", &self.target)
            .field("service", &self.service)
            .field("user", &self.user)
            .field("password_content_type", &self.password_content_type)
            .field("secret_content_type", &self.secret_content_type)
            .finish()
    }
}

impl Specifier {
    /// Create a specifier.
    pub(crate) fn new(
        ss: Arc<Service<'static>>,
        label: Option<&str>,
        target: Option<&str>,
        service: &str,
        user: &str,
        password_content_type: Option<&str>,
        secret_content_type: Option<&str>,
    ) -> Arc<Self> {
        let label = match label {
            None => format!("keyring:{user}@{service}"),
            Some(l) => l.to_string(),
        };
        Arc::new(Self {
            ss,
            label,
            target: target.map(|s| s.to_string()),
            service: service.to_string(),
            user: user.to_string(),
            password_content_type: password_content_type.unwrap_or(TEXT).to_string(),
            secret_content_type: secret_content_type.unwrap_or(BINARY).to_string(),
        })
    }

    /// Returns the label on an existing, matching item.
    ///
    /// This may or may not match the one in the specifier.
    pub fn get_label(&self) -> Result<String> {
        let path = self.get_unique_item()?;
        self.ss.get_label(&path)
    }

    /// Sets the label on an existing, matching item.
    ///
    /// Note that this doesn't update the specifier. If you delete
    /// the item and recreate it, the label will come from the specifier.
    pub fn set_label(&self, label: &str) -> Result<()> {
        let path = self.get_unique_item()?;
        self.ss.set_label(&path, label)
    }

    /// Deletes the target collection in the specifier
    pub fn delete_target(&self) -> Result<()> {
        match self.target.clone() {
            None => Err(Error::Invalid("target".to_string(), "not set".to_string())),
            Some(s) => self.ss.delete_collection(&s),
        }
    }

    fn get_unique_item(&self) -> Result<OwnedObjectPath> {
        let paths = self.ss.find_matching_items(&self.search_attributes())?;
        match paths.len() {
            0 => Err(Error::NoEntry),
            1 => Ok(paths[0].clone()),
            _ => {
                let mut entries: Vec<Entry> = Vec::with_capacity(paths.len());
                for path in paths {
                    entries.push(Entry::new_with_credential(Wrapper::new(
                        self.ss.clone(),
                        path,
                    )))
                }
                Err(Error::Ambiguous(entries))
            }
        }
    }

    /// Sets the secret of the unique matching item, creating one if there is
    /// none, declaring the given content type.
    fn set(&self, secret: &[u8], content_type: &str) -> Result<()> {
        // first try to find a unique, existing, matching item and set its password
        match self.get_unique_item() {
            Ok(p) => return self.ss.set_secret(&p, secret, content_type),
            Err(Error::NoEntry) => {}
            Err(err) => return Err(err),
        }
        // if there is no existing item, create one for this credential.
        let collection = self.target.clone().unwrap_or("default".to_string());
        self.ss.create_item(
            &collection,
            &self.label,
            self.search_attributes(),
            secret,
            content_type,
        )
    }

    /// Provide a HashMap of search attributes for this specifier.
    fn search_attributes(&self) -> HashMap<&str, &str> {
        let mut result: HashMap<&str, &str> = HashMap::new();
        result.insert("service", self.service.as_str());
        result.insert("username", self.user.as_str());
        if let Some(target) = &self.target {
            result.insert("target", target.as_str());
        }
        result
    }
}

impl CredentialApi for Specifier {
    /// See the keyring-core API docs.
    ///
    /// Passwords are stored as text (`text/plain`), so that Secret Service
    /// implementations which care about the content type (KeePassXC, the
    /// KDE Wallet) keep them as passwords, unless the specifier was created
    /// with a `password-content-type` modifier.
    fn set_password(&self, password: &str) -> Result<()> {
        self.set(password.as_bytes(), &self.password_content_type)
    }

    /// See the keyring-core API docs.
    ///
    /// Secrets are stored as `application/octet-stream`, since they needn't
    /// be text, unless the specifier was created with a
    /// `secret-content-type` modifier.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.set(secret, &self.secret_content_type)
    }

    /// See the keyring-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        let path = self.get_unique_item()?;
        self.ss.get_secret(&path)
    }

    /// See the keyring-core API docs.
    ///
    /// Besides the item's attributes, this returns the content type of its
    /// secret as `content-type`.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        let path = self.get_unique_item()?;
        get_attributes(&self.ss, &path)
    }

    /// See the keyring-core API docs.
    ///
    /// Updating `content-type` stores the secret again with that content type.
    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        for key in attributes.keys() {
            if *key == "target" || *key == "service" || *key == "username" {
                return Err(Error::Invalid(
                    key.to_string(),
                    "cannot be updated".to_string(),
                ));
            }
        }
        let path = self.get_unique_item()?;
        update_attributes(&self.ss, &path, attributes)
    }

    /// See the keyring-core API docs.
    fn delete_credential(&self) -> Result<()> {
        let path = self.get_unique_item()?;
        self.ss.delete(&path)
    }

    /// See the keyring-core API docs.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        let path = self.get_unique_item()?;
        Ok(Some(Wrapper::new(self.ss.clone(), path)))
    }

    /// See the keyring-core API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        Some((self.service.clone(), self.user.clone()))
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// See the keyring-core API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// A wrapper around a secret-service item.
///
/// Items in the Secret Service are uniquely identified by their path,
/// but the path is (per the spec) not supposed to be exposed to clients,
/// so it's held privately. It is available to the debugger.
pub struct Wrapper {
    ss: Arc<Service<'static>>,
    path: OwnedObjectPath,
}

impl std::fmt::Debug for Wrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wrapper").field("path", &self.path).finish()
    }
}

impl Wrapper {
    pub(crate) fn new(ss: Arc<Service<'static>>, path: OwnedObjectPath) -> Arc<Self> {
        Arc::new(Self { ss, path })
    }

    /// Returns the label on the wrapped item.
    pub fn get_label(&self) -> Result<String> {
        self.ss.ensure_unlocked(&self.path)?;
        self.ss.get_label(&self.path)
    }

    /// Sets the label on the wrapped item.
    pub fn set_label(&self, label: &str) -> Result<()> {
        self.ss.ensure_unlocked(&self.path)?;
        self.ss.set_label(&self.path, label)
    }

    /// Gets the path of the wrapped item.
    pub fn get_path(&self) -> String {
        self.path.to_string()
    }
}

impl CredentialApi for Wrapper {
    /// See the keyring-core API docs.
    ///
    /// Passwords are stored as text (`text/plain`), as in [Specifier].
    fn set_password(&self, password: &str) -> Result<()> {
        self.ss.ensure_unlocked(&self.path)?;
        self.ss.set_secret(&self.path, password.as_bytes(), TEXT)
    }

    /// See the keyring-core API docs.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        self.ss.ensure_unlocked(&self.path)?;
        self.ss.set_secret(&self.path, secret, BINARY)
    }

    /// See the keyring-core API docs.
    fn get_secret(&self) -> Result<Vec<u8>> {
        self.ss.ensure_unlocked(&self.path)?;
        self.ss.get_secret(&self.path)
    }

    /// See the keyring-core API docs.
    ///
    /// As in [Specifier], this includes the content type as `content-type`.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        self.ss.ensure_unlocked(&self.path)?;
        get_attributes(&self.ss, &self.path)
    }

    /// See the keyring-core API docs.
    ///
    /// As in [Specifier], updating `content-type` stores the secret again
    /// with that content type.
    fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        self.ss.ensure_unlocked(&self.path)?;
        update_attributes(&self.ss, &self.path, attributes)
    }

    /// See the keyring-core API docs.
    fn delete_credential(&self) -> Result<()> {
        self.ss.ensure_unlocked(&self.path)?;
        self.ss.delete(&self.path)
    }

    /// See the keyring-core API docs.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        self.ss.ensure_unlocked(&self.path)?;
        Ok(None)
    }

    /// See the keyring-core API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        if self.ss.ensure_unlocked(&self.path).is_err() {
            return None;
        }
        let attributes = self.ss.get_attributes(&self.path).unwrap_or_default();
        if let Some(service) = attributes.get("service")
            && let Some(user) = attributes.get("username")
        {
            return Some((service.to_string(), user.to_string()));
        }
        None
    }

    /// See the keyring-core API docs.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// See the keyring-core API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Returns an item's attributes, with the content type of its secret
/// as `content-type`.
fn get_attributes(ss: &Service, path: &OwnedObjectPath) -> Result<HashMap<String, String>> {
    let mut attributes = ss.get_attributes(path)?;
    attributes.insert("content-type".to_string(), ss.get_content_type(path)?);
    Ok(attributes)
}

/// Updates an item's attributes, storing its secret again if `content-type`
/// is among them.
fn update_attributes(
    ss: &Service,
    path: &OwnedObjectPath,
    attributes: &HashMap<&str, &str>,
) -> Result<()> {
    let content_type = attributes.get("content-type");
    if content_type.is_some_and(|c| c.is_empty()) {
        return Err(Error::Invalid(
            "content-type".to_string(),
            "cannot be empty".to_string(),
        ));
    }
    let mut attributes = attributes.clone();
    attributes.remove("content-type");
    if !attributes.is_empty() {
        ss.update_attributes(path, &attributes)?;
    }
    if let Some(content_type) = content_type {
        ss.set_content_type(path, content_type)?;
    }
    Ok(())
}
