use std::sync::Arc;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
use eframe::egui;
use vault_core::sync::SyncApi;
use vault_core::{Account, LocalMeta, LocalStore};

use crate::api::VaultApi;
use crate::config::{ClientConfig, ThemePref};
use crate::platform;
use crate::state::{Screen, SetupForm, SyncStatus};
use crate::ui::main::MainView;
use crate::ui::setup::{SetupEvent, start_setup, validate_setup};
use crate::ui::unlock::{UnlockEvent, start_unlock};
use crate::workers::vault::{VaultEvent, VaultHandle, spawn_vault};

pub struct VaultApp {
    pub config: ClientConfig,
    pub screen: Screen,
    pub setup_form: SetupForm,
    pub unlock_password: String,
    pub recovery_code: Option<String>,
    pub error: Option<String>,
    pub local_meta: Option<LocalMeta>,
    pub setup_rx: Option<Receiver<SetupEvent>>,
    pub unlock_rx: Option<Receiver<UnlockEvent>>,
    pub vault: Option<VaultHandle>,
    pub accounts: Vec<Account>,
    pub main_view: MainView,
    #[allow(dead_code)]
    pub last_activity: Instant,
    #[allow(dead_code)]
    pub toast: Option<(String, Instant)>,
    pub api: Option<Arc<VaultApi>>,
    pub sync_status: SyncStatus,
}

impl VaultApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let config_path = platform::config_path();
        let config = ClientConfig::load(&config_path);

        match config.theme {
            ThemePref::Light => cc.egui_ctx.set_visuals(egui::Visuals::light()),
            ThemePref::Dark => cc.egui_ctx.set_visuals(egui::Visuals::dark()),
            ThemePref::System => {}
        }

        let db_path = platform::db_path();
        let mut screen = Screen::Setup;
        let mut local_meta = None;

        if db_path.exists()
            && let Ok(store) = LocalStore::open(&db_path)
            && let Ok(Some(meta)) = store.load_meta()
        {
            local_meta = Some(meta);
            screen = Screen::Unlock;
        }

        let setup_form = SetupForm::from_config(&config);

        Self {
            config,
            screen,
            setup_form,
            unlock_password: String::new(),
            recovery_code: None,
            error: None,
            local_meta,
            setup_rx: None,
            unlock_rx: None,
            vault: None,
            accounts: Vec::new(),
            main_view: MainView::default(),
            last_activity: Instant::now(),
            toast: None,
            api: None,
            sync_status: SyncStatus::default(),
        }
    }

    pub fn lock(&mut self) {
        if let Some(handle) = self.vault.take() {
            handle.shutdown();
        }
        self.accounts.clear();
        self.unlock_password.clear();
        self.main_view.clear_sensitive();
        self.api = None;
        self.sync_status = SyncStatus::default();
        self.screen = Screen::Unlock;
    }

    pub fn render_setup(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading("Thiết lập Gmail Vault");
            ui.add_space(10.0);
        });

        egui::Grid::new("setup_form_grid")
            .num_columns(2)
            .spacing([12.0, 10.0])
            .show(ui, |ui| {
                ui.label("Server URL:");
                ui.text_edit_singleline(&mut self.setup_form.server_url);
                ui.end_row();

                ui.label("Email:");
                ui.text_edit_singleline(&mut self.setup_form.email);
                ui.end_row();

                ui.label("Master Password (>= 12 ký tự):");
                ui.add(egui::TextEdit::singleline(&mut self.setup_form.password).password(true));
                ui.end_row();

                ui.label("Xác nhận Master Password:");
                ui.add(egui::TextEdit::singleline(&mut self.setup_form.confirm).password(true));
                ui.end_row();
            });

        ui.add_space(12.0);

        if let Some(ref err) = self.error {
            ui.colored_label(egui::Color32::RED, err);
            ui.add_space(8.0);
        }

        if self.setup_rx.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Đang thiết lập và đăng ký vault...");
            });
        } else {
            ui.horizontal(|ui| {
                if ui.button("Tạo Vault").clicked() {
                    match validate_setup(
                        &self.setup_form.server_url,
                        &self.setup_form.email,
                        &self.setup_form.password,
                        &self.setup_form.confirm,
                    ) {
                        Ok(()) => {
                            self.error = None;
                            let mut cfg = self.config.clone();
                            cfg.server_url = self.setup_form.server_url.clone();
                            cfg.email = Some(self.setup_form.email.clone());
                            self.setup_rx = Some(start_setup(
                                cfg,
                                self.setup_form.email.clone(),
                                self.setup_form.password.clone(),
                            ));
                        }
                        Err(e) => {
                            self.error = Some(e);
                        }
                    }
                }

                if self.local_meta.is_some() && ui.button("Đã có vault? Mở khóa").clicked() {
                    self.error = None;
                    self.screen = Screen::Unlock;
                }
            });
        }
    }

    pub fn render_recovery(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading("Mã khôi phục Vault");
            ui.add_space(10.0);
        });

        ui.label(
            "LƯU Ý QUAN TRỌNG: Đây là mã duy nhất để khôi phục tài khoản nếu bạn quên Master Password.",
        );
        ui.label(
            "Hãy lưu trữ mã này ở nơi an toàn. Không ai khác có thể khôi phục dữ liệu cho bạn nếu mất mã này!",
        );
        ui.add_space(12.0);

        if let Some(ref code) = self.recovery_code {
            ui.group(|ui| {
                ui.monospace(code);
            });
            ui.add_space(8.0);
            if ui.button("Sao chép mã vào clipboard").clicked() {
                ui.ctx().copy_text(code.clone());
            }
        }

        ui.add_space(16.0);
        if ui.button("Tôi đã lưu mã khôi phục - Tiếp tục").clicked() {
            self.recovery_code = None;
            self.screen = Screen::Unlock;
        }
    }

    pub fn render_unlock(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading("Mở khóa Gmail Vault");
            ui.add_space(10.0);
        });

        if let Some(ref meta) = self.local_meta {
            ui.label(format!("Tài khoản: {}", meta.email));
            ui.label(format!("Server: {}", meta.server_url));
            ui.add_space(8.0);
        } else if let Some(ref email) = self.config.email {
            ui.label(format!("Tài khoản: {email}"));
            ui.add_space(8.0);
        }

        ui.horizontal(|ui| {
            ui.label("Master Password:");
            let resp = ui.add(egui::TextEdit::singleline(&mut self.unlock_password).password(true));
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));

            let clicked = ui.button("Mở khóa").clicked();
            if (clicked || enter) && self.unlock_rx.is_none() {
                if let Some(ref meta) = self.local_meta {
                    self.error = None;
                    self.unlock_rx = Some(start_unlock(
                        meta.clone(),
                        self.unlock_password.clone(),
                        platform::db_path(),
                    ));
                } else {
                    self.error = Some(
                        "Không tìm thấy thông tin vault cục bộ. Vui lòng thiết lập lại.".into(),
                    );
                }
            }
        });

        ui.add_space(10.0);

        if let Some(ref err) = self.error {
            ui.colored_label(egui::Color32::RED, err);
            ui.add_space(8.0);
        }

        if self.unlock_rx.is_some() {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Đang giải mã vault...");
            });
        }

        ui.add_space(16.0);
        if ui.button("Thiết lập lại hoặc tạo vault mới").clicked() {
            self.error = None;
            self.screen = Screen::Setup;
        }
    }

    #[allow(dead_code)]
    pub fn render_fatal(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.colored_label(egui::Color32::RED, "Lỗi nghiêm trọng");
            ui.add_space(10.0);
        });

        if let Some(ref err) = self.error {
            ui.label(err);
        }

        ui.add_space(16.0);
        if ui.button("Về màn hình thiết lập").clicked() {
            self.error = None;
            self.screen = Screen::Setup;
        }
    }
}

impl eframe::App for VaultApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if ctx.input(|i| !i.events.is_empty()) {
            self.last_activity = Instant::now();
        }

        // Poll background tasks
        if let Some(ref rx) = self.setup_rx
            && let Ok(event) = rx.try_recv()
        {
            self.setup_rx = None;
            match event {
                SetupEvent::Done { recovery_code } => {
                    self.error = None;
                    self.recovery_code = Some(recovery_code);
                    self.screen = Screen::ShowRecovery;
                    self.config.server_url = self.setup_form.server_url.clone();
                    self.config.email = Some(self.setup_form.email.clone());
                    let _ = self.config.save(&platform::config_path());
                    if let Ok(store) = LocalStore::open(&platform::db_path())
                        && let Ok(Some(meta)) = store.load_meta()
                    {
                        self.local_meta = Some(meta);
                    }
                }
                SetupEvent::Failed(err) => {
                    self.error = Some(err);
                }
            }
        }

        if let Some(ref rx) = self.unlock_rx
            && let Ok(event) = rx.try_recv()
        {
            self.unlock_rx = None;
            match event {
                UnlockEvent::Done(session) => {
                    self.error = None;
                    let session = *session;
                    let api = Arc::new(VaultApi::new(&session.meta.server_url));
                    api.set_email(&session.meta.email);
                    self.api = Some(api.clone());
                    let sync_api: Arc<dyn SyncApi> = api;
                    let interval =
                        Duration::from_secs(self.config.sync_interval_secs.clamp(15, 600));
                    let handle = spawn_vault(
                        session.meta,
                        session.vault,
                        session.store,
                        session.accounts.clone(),
                        platform::db_path(),
                        platform::backup_dir(),
                        sync_api,
                        interval,
                    );
                    self.accounts = session.accounts;
                    self.vault = Some(handle);
                    self.sync_status = SyncStatus::default();
                    self.screen = Screen::Main;
                    self.last_activity = Instant::now();
                }
                UnlockEvent::Failed(err) => {
                    self.error = Some(err);
                }
            }
        }

        if let Some(ref handle) = self.vault {
            while let Ok(event) = handle.rx.try_recv() {
                match event {
                    VaultEvent::Accounts(accounts) => {
                        self.main_view.retain_ids(&accounts);
                        self.accounts = accounts;
                    }
                    VaultEvent::Error(err) => {
                        self.error = Some(err);
                    }
                    VaultEvent::BackupDone(path) => {
                        self.toast =
                            Some((format!("Đã backup: {}", path.display()), Instant::now()));
                    }
                    VaultEvent::SyncStatus(s) => {
                        self.sync_status = s;
                    }
                }
            }
        }

        if self.setup_rx.is_some() || self.unlock_rx.is_some() || self.vault.is_some() {
            ctx.request_repaint();
        }

        match self.screen {
            Screen::Main => {
                if let Some(ref handle) = self.vault {
                    if self
                        .main_view
                        .show(ctx, &self.accounts, &self.sync_status, handle)
                    {
                        self.lock();
                    }
                } else {
                    self.lock();
                }
            }
            Screen::Setup => {
                egui::CentralPanel::default().show(ctx, |ui| self.render_setup(ui));
            }
            Screen::ShowRecovery => {
                egui::CentralPanel::default().show(ctx, |ui| self.render_recovery(ui));
            }
            Screen::Unlock => {
                egui::CentralPanel::default().show(ctx, |ui| self.render_unlock(ui));
            }
            Screen::Fatal => {
                egui::CentralPanel::default().show(ctx, |ui| self.render_fatal(ui));
            }
        }
    }
}
