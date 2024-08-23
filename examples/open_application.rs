use near_ledger::{open_near_application, NEARLedgerError};

fn main() -> Result<(), NEARLedgerError> {
    env_logger::builder().init();

    open_near_application()?;

    Ok(())
}
