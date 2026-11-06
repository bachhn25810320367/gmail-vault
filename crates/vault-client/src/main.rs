use eframe::egui;

pub mod api;
pub mod app;
pub mod config;
pub mod platform;
pub mod state;
pub mod ui;

fn main() -> eframe::Result {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([720.0, 520.0])
            .with_min_inner_size([480.0, 360.0])
            .with_title("Gmail Vault"),
        ..Default::default()
    };

    eframe::run_native(
        "Gmail Vault",
        options,
        Box::new(|cc| Ok(Box::new(app::VaultApp::new(cc)))),
    )
}
