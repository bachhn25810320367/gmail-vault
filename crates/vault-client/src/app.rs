use crossbeam_channel::Receiver;
use eframe::egui;
use vault_core::{LocalMeta, LocalStore};

use crate::config::{ClientConfig, ThemePref};
use crate::platform;
use crate::state::{Screen, SetupForm, UnlockedSession};
use crate::ui::setup::{SetupEvent, start_setup, validate_setup};
use crate::ui::unlock::{UnlockEvent, start_unlock};

pub struct VaultApp {
    pub config: ClientConfig,
    pub screen: Screen,
    pub setup_form: SetupForm,
    pub unlock_password: String,
    pub recovery_code: Option<String>,
    pub error: Option<String>,
    pub session: Option<UnlockedSession>,
    pub local_meta: Option<LocalMeta>,
    pub setup_rx: Option<Receiver<SetupEvent>>,
    pub unlock_rx: Option<Receiver<UnlockEvent>>,
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
            session: None,
            local_meta,
            setup_rx: None,
            unlock_rx: None,
        }
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

    pub fn render_placeholder_main(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading("Gmail Vault - Đã mở khóa");
            ui.add_space(10.0);
        });

        if let Some(ref session) = self.session {
            ui.label(format!("Tài khoản: {}", session.meta.email));
            ui.label(format!("Số lượng bản ghi: {}", session.accounts.len()));
        }

        ui.add_space(16.0);
        if ui.button("Khóa Vault").clicked() {
            self.session = None;
            self.unlock_password.clear();
            self.screen = Screen::Unlock;
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
                    self.session = Some(*session);
                    self.screen = Screen::Main;
                }
                UnlockEvent::Failed(err) => {
                    self.error = Some(err);
                }
            }
        }

        if self.setup_rx.is_some() || self.unlock_rx.is_some() {
            ctx.request_repaint();
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.screen {
            Screen::Setup => self.render_setup(ui),
            Screen::ShowRecovery => self.render_recovery(ui),
            Screen::Unlock => self.render_unlock(ui),
            Screen::Main => self.render_placeholder_main(ui),
            Screen::Fatal => self.render_fatal(ui),
        });
    }
}
