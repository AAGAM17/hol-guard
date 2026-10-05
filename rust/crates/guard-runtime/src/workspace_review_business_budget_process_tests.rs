use super::*;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

struct Children(Vec<Child>);
impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while !path.exists() {
        assert!(Instant::now() < deadline, "process barrier timed out");
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
#[ignore = "subprocess entry invoked only by independent_processes_share_one_allowance"]
fn reservation_child() {
    let root = PathBuf::from(std::env::var_os("HOL_BUDGET_TEST_ROOT").unwrap());
    let id = std::env::var("HOL_BUDGET_TEST_CHILD").unwrap();
    assert!(matches!(id.as_str(), "left" | "right"));
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let now = store.current_snapshot().unwrap().issued_at_ms + 1;
    std::fs::write(root.join(format!("ready-{id}")), b"ready").unwrap();
    wait_for(&root.join("start-process-reservations"));
    let result = reserve_at(
        &store,
        &format!("budget-process-{id}"),
        &prepared(),
        &actor(),
        now,
    );
    let status = match result {
        Ok(_) => "reserved",
        Err(error) => {
            assert!(matches!(
                error.as_str(),
                "native_business_budget_exceeded" | "native_approval_authority_busy"
            ));
            "refused"
        }
    };
    std::fs::write(root.join(format!("result-{id}")), status).unwrap();
    wait_for(&root.join(format!("verify-{id}")));
    assert_eq!(
        reserve_at(
            &store,
            &format!("budget-process-retry-{id}"),
            &prepared(),
            &actor(),
            now + 1
        )
        .err()
        .unwrap(),
        "native_business_budget_exceeded"
    );
    std::fs::write(root.join(format!("verified-{id}")), b"budget_exceeded").unwrap();
}

#[test]
fn independent_processes_share_one_allowance() {
    let fixture = Fixture::new("business-budget-independent-processes");
    let mut budget = declaration("account");
    budget["maximumActions"] = json!(1);
    install(&fixture, json!([budget]));
    let mut children = Children(Vec::new());
    // libtest names omit the crate prefix included by module_path!().
    let test_module = module_path!().split_once("::").unwrap().1;
    for id in ["left", "right"] {
        children.0.push(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("{test_module}::reservation_child"),
                    "--ignored",
                    "--nocapture",
                ])
                .env("HOL_BUDGET_TEST_ROOT", &fixture.root)
                .env("HOL_BUDGET_TEST_CHILD", id)
                .spawn()
                .unwrap(),
        );
    }
    for id in ["left", "right"] {
        wait_for(&fixture.root.join(format!("ready-{id}")));
    }
    std::fs::write(fixture.root.join("start-process-reservations"), b"start").unwrap();
    for id in ["left", "right"] {
        wait_for(&fixture.root.join(format!("result-{id}")));
    }
    // Serialize the post-race checks so neither can hide behind a busy lock.
    for id in ["left", "right"] {
        std::fs::write(fixture.root.join(format!("verify-{id}")), b"verify").unwrap();
        wait_for(&fixture.root.join(format!("verified-{id}")));
    }
    for child in &mut children.0 {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "reservation child timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    let winners = ["left", "right"]
        .into_iter()
        .filter(|id| {
            std::fs::read_to_string(fixture.root.join(format!("result-{id}"))).unwrap()
                == "reserved"
        })
        .count();
    assert_eq!(winners, 1);
    let reopened = PolicySnapshotStore::new(&fixture.root, &"a".repeat(64)).unwrap();
    assert_eq!(
        reserve_at(
            &reopened,
            "budget-process-reopened",
            &prepared(),
            &actor(),
            time(&fixture) + 1
        )
        .err()
        .unwrap(),
        "native_business_budget_exceeded"
    );
    assert_eq!(load(&fixture.root).unwrap().0.events.len(), 1);
}
