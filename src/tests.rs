use std::collections::HashMap;
use std::sync::{Arc, Once};

use super::{Store, cred::Specifier};
use crate::cred::Wrapper;
use keyring_core::{CredentialStore, Entry, Error, api::CredentialPersistence, get_default_store};

static SET_STORE: Once = Once::new();

fn usually_goes_in_main() {
    keyring_core::set_default_store(Store::new().unwrap());
}

#[test]
fn test_store_methods() {
    SET_STORE.call_once(usually_goes_in_main);
    let store = get_default_store().unwrap();
    let vendor1a = store.vendor();
    let id1a = store.id();
    let vendor1b = store.vendor();
    let id1b = store.id();
    assert_eq!(vendor1a, vendor1b);
    assert_eq!(id1a, id1b);
    let store2: Arc<CredentialStore> = Store::new().unwrap();
    let vendor2 = store2.vendor();
    let id2 = store2.id();
    assert_eq!(vendor1a, vendor2);
    assert_ne!(id1a, id2);
}

fn entry_new(service: &str, user: &str) -> Entry {
    SET_STORE.call_once(usually_goes_in_main);
    Entry::new(service, user).unwrap_or_else(|err| {
        panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
    })
}

fn entry_new_with_target(target: &str, service: &str, user: &str) -> Entry {
    SET_STORE.call_once(usually_goes_in_main);
    let modifiers = HashMap::from([("target", target)]);
    Entry::new_with_modifiers(service, user, &modifiers).unwrap_or_else(|err| {
        panic!(
            "Couldn't create entry (service: {service}, user: {user}, target: {target}): {err:?}"
        )
    })
}

fn entry_new_with_modifiers(service: &str, user: &str, modifiers: &HashMap<&str, &str>) -> Entry {
    SET_STORE.call_once(usually_goes_in_main);
    Entry::new_with_modifiers(service, user, modifiers).unwrap_or_else(|err| {
        panic!(
            "Couldn't create entry (service: {service}, user: {user}, modifiers: {modifiers:?}): {err:?}"
        )
    })
}

fn generate_random_string() -> String {
    use fastrand;
    use std::iter::repeat_with;
    let s: String = repeat_with(fastrand::alphanumeric).take(12).collect();
    format!("test-{s}")
}

fn generate_random_bytes() -> Vec<u8> {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(|| fastrand::u8(..)).take(24).collect()
}

// A round-trip password test that doesn't delete the credential afterward
fn test_round_trip_no_delete(case: &str, entry: &Entry, in_pass: &str) {
    entry
        .set_password(in_pass)
        .unwrap_or_else(|err| panic!("Can't set password for {case}: {err:?}"));
    let out_pass = entry
        .get_password()
        .unwrap_or_else(|err| panic!("Can't get password: {case}: {err:?}"));
    assert_eq!(
        in_pass, out_pass,
        "Passwords don't match for {case}: set='{in_pass}', get='{out_pass}'",
    )
}

// A round-trip password test that does delete the credential afterward
fn test_round_trip(case: &str, entry: &Entry, in_pass: &str) {
    test_round_trip_no_delete(case, entry, in_pass);
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete password: {case}: {err:?}"));
    let password = entry.get_password();
    assert!(
        matches!(password, Err(Error::NoEntry)),
        "Got a deleted password: {case}",
    );
}

// A round-trip secret test that does delete the credential afterward
fn test_round_trip_secret(case: &str, entry: &Entry, in_secret: &[u8]) {
    entry
        .set_secret(in_secret)
        .unwrap_or_else(|err| panic!("Can't set secret for {case}: {err:?}"));
    let out_secret = entry
        .get_secret()
        .unwrap_or_else(|err| panic!("Can't get secret for {case}: {err:?}"));
    assert_eq!(
        in_secret, &out_secret,
        "Secrets don't match for {case}: set='{in_secret:?}', get='{out_secret:?}'",
    );
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete credential for {case}: {err:?}"));
    let secret = entry.get_secret();
    assert!(
        matches!(secret, Err(Error::NoEntry)),
        "Got a deleted password: {case}",
    );
}

#[test]
fn test_invalid_parameter() {
    SET_STORE.call_once(usually_goes_in_main);
    let modifiers = HashMap::from([("target", "")]);
    let entry = Entry::new_with_modifiers("service", "user", &modifiers);
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
    let modifiers = HashMap::from([("label", "")]);
    let entry = Entry::new_with_modifiers("service", "user", &modifiers);
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
    let modifiers = HashMap::from([("password-content-type", "")]);
    let entry = Entry::new_with_modifiers("service", "user", &modifiers);
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
    let modifiers = HashMap::from([("secret-content-type", "")]);
    let entry = Entry::new_with_modifiers("service", "user", &modifiers);
    assert!(matches!(entry, Err(Error::Invalid(_, _))));
    let store = Store::new_with_configuration(&HashMap::from([("anything", "anything")]));
    assert!(matches!(store, Err(Error::NotSupportedByStore(_))));
}

#[test]
fn test_missing_entry() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_empty_password() {
    let name = generate_random_string();
    let in_pass = "";
    let entry = entry_new(&name, &name);
    entry.set_password(in_pass).unwrap();
    assert_eq!(entry.get_password().unwrap(), in_pass);
    entry.delete_credential().unwrap();
}

#[test]
fn test_round_trip_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("ascii password", &entry, "test ascii password");
}

#[test]
fn test_round_trip_non_ascii_password() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip("non-ascii password", &entry, "このきれいな花は桜です");
}

#[test]
fn test_entries_with_same_and_different_specifiers() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    let entry2 = entry_new(&name1, &name2);
    let entry3 = entry_new(&name2, &name1);
    entry1.set_password("test password").unwrap();
    let pw2 = entry2.get_password().unwrap();
    assert_eq!(pw2, "test password");
    _ = entry3.get_password().unwrap_err();
    entry1.delete_credential().unwrap();
    _ = entry2.get_password().unwrap_err();
    entry3.delete_credential().unwrap_err();
}

#[test]
fn test_round_trip_random_secret() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let secret = generate_random_bytes();
    test_round_trip_secret("non-ascii password", &entry, secret.as_slice());
}

#[test]
fn test_update() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    test_round_trip_no_delete("initial ascii password", &entry, "test ascii password");
    test_round_trip(
        "updated non-ascii password",
        &entry,
        "このきれいな花は桜です",
    );
}

#[test]
fn test_update_secret() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    // 0xFF can never appear in UTF-8, so these secrets are unambiguously binary
    let mut initial = generate_random_bytes();
    initial.push(0xFF);
    entry
        .set_secret(&initial)
        .unwrap_or_else(|err| panic!("Can't set initial secret: {err:?}"));
    let mut updated = generate_random_bytes();
    updated.push(0xFF);
    test_round_trip_secret("updated binary secret", &entry, &updated);
}

// Checks the content type that the Secret Service reports for a credential's
// secret, as its keyring:content-type attribute. GNOME Keyring doesn't keep
// content types and reports text/plain for every secret, so text/plain where
// another content type was expected only counts as ignored.
fn check_content_type(cred: &Entry, expected: &str, case: &str, ignored: &mut usize) {
    let attributes = cred
        .get_attributes()
        .unwrap_or_else(|err| panic!("Can't get attributes for {case}: {err:?}"));
    let actual = attributes
        .get("keyring:content-type")
        .unwrap_or_else(|| panic!("No content type for {case}"));
    if actual != expected {
        assert_eq!(actual, "text/plain", "Content types don't match for {case}");
        *ignored += 1;
    }
}

#[test]
fn test_alternate_passwords_and_secrets() {
    // Passwords and secrets are set with different content types; an item
    // can switch between them, also through a wrapper.
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let mut secret = generate_random_bytes();
    // 0xFF can never appear in UTF-8, so this secret is unambiguously binary
    secret.push(0xFF);
    test_round_trip_no_delete("created password", &entry, "a password");
    entry.set_secret(&secret).unwrap();
    assert_eq!(entry.get_secret().unwrap(), secret, "password to secret");
    test_round_trip_no_delete("secret to password", &entry, "このパスワード");
    let wrapper = entry.get_credential().unwrap();
    wrapper.set_secret(&secret).unwrap();
    assert_eq!(entry.get_secret().unwrap(), secret, "wrapper secret");
    wrapper.set_password("through a wrapper").unwrap();
    assert_eq!(entry.get_password().unwrap(), "through a wrapper");
    entry.delete_credential().unwrap();
}

#[test]
fn test_content_types() {
    // Passwords and secrets are stored with the default content types, or
    // with those of the entry's modifiers, and an item's content type can be
    // updated; none of this changes the secret. The modifiers swap the
    // defaults, as every Secret Service implementation accepts both.
    let mut ignored = 0;
    let name = generate_random_string();
    let secret = generate_random_bytes();
    let entry = entry_new(&name, &name);
    let specifier = entry.as_any().downcast_ref::<Specifier>().unwrap();
    assert_eq!(specifier.password_content_type, "text/plain");
    assert_eq!(specifier.secret_content_type, "application/octet-stream");
    entry.set_password("a password").unwrap();
    check_content_type(&entry, "text/plain", "default password", &mut ignored);
    entry.set_secret(&secret).unwrap();
    check_content_type(
        &entry,
        "application/octet-stream",
        "default secret",
        &mut ignored,
    );
    let wrapper = entry.get_credential().unwrap();
    wrapper.set_password("through a wrapper").unwrap();
    check_content_type(&wrapper, "text/plain", "wrapper password", &mut ignored);
    wrapper.set_secret(&secret).unwrap();
    check_content_type(
        &wrapper,
        "application/octet-stream",
        "wrapper secret",
        &mut ignored,
    );
    entry.delete_credential().unwrap();

    let modifiers = HashMap::from([
        ("password-content-type", "application/octet-stream"),
        ("secret-content-type", "text/plain"),
    ]);
    let entry = entry_new_with_modifiers(&name, &name, &modifiers);
    let specifier = entry.as_any().downcast_ref::<Specifier>().unwrap();
    assert_eq!(specifier.password_content_type, "application/octet-stream");
    assert_eq!(specifier.secret_content_type, "text/plain");
    entry.set_password("a password").unwrap();
    check_content_type(
        &entry,
        "application/octet-stream",
        "password from modifier",
        &mut ignored,
    );
    // Valid UTF-8, as the KDE Wallet rejects anything else as text/plain
    let text_secret = b"a text secret";
    entry.set_secret(text_secret).unwrap();
    check_content_type(&entry, "text/plain", "secret from modifier", &mut ignored);
    entry
        .update_attributes(&HashMap::from([(
            "keyring:content-type",
            "application/octet-stream",
        )]))
        .unwrap();
    check_content_type(
        &entry,
        "application/octet-stream",
        "updated attribute",
        &mut ignored,
    );
    assert_eq!(entry.get_secret().unwrap(), text_secret);
    let wrapper = entry.get_credential().unwrap();
    wrapper
        .update_attributes(&HashMap::from([("keyring:content-type", "text/plain")]))
        .unwrap();
    check_content_type(
        &wrapper,
        "text/plain",
        "updated wrapper attribute",
        &mut ignored,
    );
    assert_eq!(entry.get_secret().unwrap(), text_secret);
    entry
        .update_attributes(&HashMap::from([("keyring:content-type", "")]))
        .unwrap_err();
    entry.delete_credential().unwrap();
    if ignored > 0 {
        eprintln!(
            "The Secret Service reported text/plain for {ignored} secrets stored \
             with other content types: it seems to ignore content types."
        );
    }
}

#[test]
fn test_get_update_attributes() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    entry1.get_attributes().unwrap_err();
    entry1.set_password("foobar").unwrap();
    let attrs = entry1.get_attributes().unwrap();
    assert!(attrs.len() >= 2);
    assert!(attrs.contains_key("service"));
    assert_eq!(attrs["service"], name1);
    assert!(attrs.contains_key("username"));
    assert_eq!(attrs["username"], name2);
    assert!(attrs.contains_key("keyring:content-type"));
    entry1
        .update_attributes(&HashMap::from([("target", "foo")]))
        .unwrap_err();
    entry1
        .update_attributes(&HashMap::from([("random", "bar")]))
        .unwrap();
    let attrs = entry1.get_attributes().unwrap();
    assert!(attrs.len() >= 3);
    assert!(attrs.contains_key("random"));
    assert_eq!(attrs["random"], "bar");
    entry1.delete_credential().unwrap();
}

#[test]
fn test_get_credential_and_specifiers_and_label() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    assert!(matches!(entry1.get_credential(), Err(Error::NoEntry)));
    entry1.set_password("password for entry1").unwrap();
    entry1.as_any().downcast_ref::<Specifier>().unwrap();
    let wrapper = entry1.get_credential().unwrap();
    let cred = wrapper.as_any().downcast_ref::<Wrapper>().unwrap();
    cred.set_label("label for entry1").unwrap();
    assert_eq!(cred.get_label().unwrap(), "label for entry1");
    let (service, user) = wrapper.get_specifiers().unwrap();
    assert_eq!(service, name1);
    assert_eq!(user, name2);
    entry1.delete_credential().unwrap();
    wrapper.delete_credential().unwrap_err();
}

#[test]
#[ignore = "Requires user interaction"]
fn test_entries_with_and_without_targets() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    entry1.set_password("entry1 password").unwrap();
    assert_eq!(entry1.get_password().unwrap(), "entry1 password");
    let entry2 = entry_new_with_target(&name2, &name1, &name2);
    entry2.set_password("entry2 password").unwrap();
    assert_eq!(entry2.get_password().unwrap(), "entry2 password");
    match entry1.get_password().unwrap_err() {
        Error::Ambiguous(wrappers) => {
            assert_eq!(wrappers.len(), 2);
            assert_eq!(
                wrappers[0].get_specifiers().unwrap(),
                (name1.clone(), name2.clone())
            );
            wrappers[0].delete_credential().unwrap();
            assert_eq!(
                wrappers[1].get_specifiers().unwrap(),
                (name1.clone(), name2.clone())
            );
            wrappers[1].delete_credential().unwrap();
        }
        err => panic!("Expected ambiguous error, got {err:?}"),
    }
    entry1.delete_credential().unwrap_err();
    entry2.delete_credential().unwrap_err();
    let entry3 = entry_new_with_target(&name2, &name1, &name2);
    entry3.set_password("entry3 password").unwrap();
    let (service, user) = entry3.get_specifiers().unwrap();
    assert_eq!(service, name1);
    assert_eq!(user, name2);
    let attributes = entry3.get_attributes().unwrap();
    assert!(attributes.len() >= 3);
    assert!(attributes.contains_key("target"));
    assert_eq!(attributes["target"], name2);
    entry3
        .as_any()
        .downcast_ref::<Specifier>()
        .unwrap()
        .delete_target()
        .unwrap();
    entry3.delete_credential().unwrap_err();
    let entry4 = entry_new_with_target("default", &name1, &name2);
    entry4.set_password("entry4 password").unwrap();
    let attributes = entry4.get_attributes().unwrap();
    assert!(attributes.len() >= 3);
    assert!(attributes.contains_key("target"));
    assert_eq!(attributes["target"], "default");
    entry4.delete_credential().unwrap();
    entry4
        .as_any()
        .downcast_ref::<Specifier>()
        .unwrap()
        .delete_target()
        .unwrap_err();
}

#[test]
fn test_create_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let test = move || {
        let password = "test ascii password";
        entry.set_password(password).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        let password = "このきれいな花は桜です";
        entry.set_password(password).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_simultaneous_create_then_move() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("{}-{}", generate_random_string(), i);
        let entry = entry_new(&name, &name);
        let test = move || {
            entry.set_password(&name).unwrap();
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_create_set_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let password = "test ascii password";
    entry.set_password(password).unwrap();
    let test = move || {
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, password);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_simultaneous_create_set_then_move() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("{}-{}", generate_random_string(), i);
        let entry = entry_new(&name, &name);
        entry.set_password(&name).unwrap();
        let test = move || {
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_simultaneous_independent_create_set() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("thread_entry{i}");
        let test = move || {
            let entry = entry_new(&name, &name);
            entry.set_password(&name).unwrap();
            let stored_password = entry.get_password().unwrap();
            assert_eq!(stored_password, name);
            entry.delete_credential().unwrap();
            assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_multiple_create_delete_single_thread() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let repeats = 10;
    for _i in 0..repeats {
        entry.set_password(&name).unwrap();
        let stored_password = entry.get_password().unwrap();
        assert_eq!(stored_password, name);
        entry.delete_credential().unwrap();
        assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    }
}

#[test]
fn test_simultaneous_multiple_create_delete_single_thread() {
    let mut handles = vec![];
    for t in 0..10 {
        let name = generate_random_string();
        let test = move || {
            let name = format!("{name}-{t}");
            let entry = entry_new(&name, &name);
            let repeats = 10;
            for _i in 0..repeats {
                entry.set_password(&name).unwrap();
                let stored_password = entry.get_password().unwrap();
                assert_eq!(stored_password, name);
                entry.delete_credential().unwrap();
                assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
            }
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().unwrap()
    }
}

#[test]
fn test_persistence() {
    let store: Arc<CredentialStore> = Store::new().unwrap();
    assert!(matches!(
        store.persistence(),
        CredentialPersistence::UntilDelete
    ));
}
