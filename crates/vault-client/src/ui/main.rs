use std::collections::BTreeSet;

use egui::{Align, Key, KeyboardShortcut, Layout, Modifiers};
use egui_extras::{Column, TableBuilder};
use uuid::Uuid;
use vault_core::{Account, AccountStatus, Plan};

use crate::state::SyncStatus;
use crate::ui::editor::EditorDraft;
use crate::ui::filters::{Filters, SortKey, SortState, sort_accounts};
use crate::workers::vault::{VaultCommand, VaultHandle};

#[allow(clippy::large_enum_variant)]
enum EditorAction {
    Save(Account),
    MarkUsed(Uuid),
    Delete(Uuid),
    Close,
}

#[derive(Default)]
pub struct MainView {
    pub filters: Filters,
    pub sort: SortState,
    pub selected: Option<Uuid>,
    pub draft: Option<EditorDraft>,
    pub confirm_delete: bool,
    pub tags_input: String,
    pub focus_search: bool,
}

impl MainView {
    pub fn clear_sensitive(&mut self) {
        self.draft = None;
        self.confirm_delete = false;
        self.selected = None;
        self.tags_input.clear();
    }

    pub fn retain_ids(&mut self, accounts: &[Account]) {
        if let Some(id) = self.selected
            && !accounts.iter().any(|a| a.id == id)
        {
            self.clear_sensitive();
        }
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        accounts: &[Account],
        sync_status: &SyncStatus,
        handle: &VaultHandle,
    ) -> bool {
        let mut lock_requested = false;

        // Shortcuts
        let shortcut_search = KeyboardShortcut::new(Modifiers::COMMAND, Key::F);
        let shortcut_new = KeyboardShortcut::new(Modifiers::COMMAND, Key::N);
        let shortcut_lock = KeyboardShortcut::new(Modifiers::COMMAND, Key::L);
        let shortcut_save = KeyboardShortcut::new(Modifiers::COMMAND, Key::S);
        let shortcut_escape = KeyboardShortcut::new(Modifiers::NONE, Key::Escape);
        let shortcut_copy_pw = KeyboardShortcut::new(
            Modifiers {
                command: true,
                shift: true,
                ..Default::default()
            },
            Key::C,
        );

        if ctx.input_mut(|i| i.consume_shortcut(&shortcut_search)) {
            self.focus_search = true;
        }
        if ctx.input_mut(|i| i.consume_shortcut(&shortcut_new)) {
            self.selected = None;
            self.draft = Some(EditorDraft::new());
            self.confirm_delete = false;
            self.tags_input.clear();
        }
        if ctx.input_mut(|i| i.consume_shortcut(&shortcut_lock)) {
            lock_requested = true;
        }
        if ctx.input_mut(|i| i.consume_shortcut(&shortcut_escape)) {
            self.draft = None;
            self.confirm_delete = false;
        }
        if ctx.input_mut(|i| i.consume_shortcut(&shortcut_copy_pw)) {
            if let Some(selected_id) = self.selected
                && let Some(acc) = accounts.iter().find(|a| a.id == selected_id)
            {
                ctx.copy_text(acc.password.clone());
            } else if let Some(ref d) = self.draft {
                ctx.copy_text(d.account.password.clone());
            }
        }
        if ctx.input_mut(|i| i.consume_shortcut(&shortcut_save))
            && let Some(ref d) = self.draft
        {
            let mut d = d.clone();
            d.account.tags = self
                .tags_input
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if d.validate().is_ok() {
                self.selected = Some(d.account.id);
                let _ = handle.tx.send(VaultCommand::Save(d.into_account()));
            }
        }

        // Top toolbar
        egui::TopBottomPanel::top("main_top_toolbar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("🔍");
                let search_edit = ui.text_edit_singleline(&mut self.filters.text);
                if self.focus_search {
                    search_edit.request_focus();
                    self.focus_search = false;
                }

                ui.separator();

                egui::ComboBox::from_id_salt("plan_combo")
                    .selected_text(match &self.filters.plan {
                        Some(p) => p.as_str(),
                        None => "Tất cả Plan",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.filters.plan, None, "Tất cả Plan");
                        ui.selectable_value(&mut self.filters.plan, Some(Plan::Free), "Free");
                        ui.selectable_value(&mut self.filters.plan, Some(Plan::Pro), "Pro");
                        ui.selectable_value(&mut self.filters.plan, Some(Plan::Ultra), "Ultra");
                    });

                egui::ComboBox::from_id_salt("status_combo")
                    .selected_text(match &self.filters.status {
                        Some(s) => s.as_str(),
                        None => "Tất cả trạng thái",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.filters.status, None, "Tất cả trạng thái");
                        ui.selectable_value(
                            &mut self.filters.status,
                            Some(AccountStatus::Active),
                            "Active",
                        );
                        ui.selectable_value(
                            &mut self.filters.status,
                            Some(AccountStatus::Banned),
                            "Banned",
                        );
                        ui.selectable_value(
                            &mut self.filters.status,
                            Some(AccountStatus::Sold),
                            "Sold",
                        );
                        ui.selectable_value(
                            &mut self.filters.status,
                            Some(AccountStatus::Deleted),
                            "Deleted",
                        );
                    });

                egui::ComboBox::from_id_salt("sort_combo")
                    .selected_text(match self.sort.key {
                        SortKey::Email => "Sắp xếp: Email",
                        SortKey::CreatedOn => "Sắp xếp: Ngày tạo",
                        SortKey::Plan => "Sắp xếp: Plan",
                        SortKey::Status => "Sắp xếp: Trạng thái",
                        SortKey::ExpiresOn => "Sắp xếp: Hết hạn",
                        SortKey::LastUsedOn => "Sắp xếp: Dùng gần nhất",
                        SortKey::UpdatedAt => "Sắp xếp: Cập nhật",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.sort.key, SortKey::Email, "Email");
                        ui.selectable_value(&mut self.sort.key, SortKey::CreatedOn, "Ngày tạo");
                        ui.selectable_value(&mut self.sort.key, SortKey::Plan, "Plan");
                        ui.selectable_value(&mut self.sort.key, SortKey::Status, "Trạng thái");
                        ui.selectable_value(&mut self.sort.key, SortKey::ExpiresOn, "Hết hạn");
                        ui.selectable_value(
                            &mut self.sort.key,
                            SortKey::LastUsedOn,
                            "Dùng gần nhất",
                        );
                        ui.selectable_value(&mut self.sort.key, SortKey::UpdatedAt, "Cập nhật");
                    });

                let sort_icon = if self.sort.descending { "⬇" } else { "⬆" };
                if ui
                    .button(sort_icon)
                    .on_hover_text("Đảo chiều sắp xếp")
                    .clicked()
                {
                    self.sort.descending = !self.sort.descending;
                }

                ui.separator();

                if ui.button("+ Tạo mới").clicked() {
                    self.selected = None;
                    self.draft = Some(EditorDraft::new());
                    self.confirm_delete = false;
                    self.tags_input.clear();
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.button("Khóa Vault").clicked() {
                        lock_requested = true;
                    }
                    if ui
                        .add_enabled(!sync_status.syncing, egui::Button::new("Sync now"))
                        .clicked()
                    {
                        let _ = handle.tx.send(VaultCommand::SyncNow);
                    }
                    if sync_status.syncing {
                        ui.spinner();
                    }
                    let label = sync_status.pending_label();
                    let resp = if sync_status.pending > 0 {
                        ui.colored_label(egui::Color32::from_rgb(230, 140, 0), &label)
                    } else if sync_status.online {
                        ui.colored_label(egui::Color32::from_rgb(0, 160, 0), &label)
                    } else {
                        ui.colored_label(egui::Color32::GRAY, &label)
                    };
                    if let Some(ref err) = sync_status.last_error {
                        resp.on_hover_text(err);
                    }
                });
            });
        });

        // Left sidebar
        egui::SidePanel::left("main_left_panel")
            .resizable(true)
            .default_width(180.0)
            .show(ctx, |ui| {
                ui.heading("Bộ lọc");
                ui.add_space(8.0);

                let total_count = accounts.len();
                let free_count = accounts.iter().filter(|a| a.plan == Plan::Free).count();
                let pro_count = accounts.iter().filter(|a| a.plan == Plan::Pro).count();
                let ultra_count = accounts.iter().filter(|a| a.plan == Plan::Ultra).count();

                if ui
                    .selectable_label(
                        self.filters.plan.is_none(),
                        format!("Tất cả ({total_count})"),
                    )
                    .clicked()
                {
                    self.filters.plan = None;
                }
                if ui
                    .selectable_label(
                        self.filters.plan == Some(Plan::Free),
                        format!("Free ({free_count})"),
                    )
                    .clicked()
                {
                    self.filters.plan = Some(Plan::Free);
                }
                if ui
                    .selectable_label(
                        self.filters.plan == Some(Plan::Pro),
                        format!("Pro ({pro_count})"),
                    )
                    .clicked()
                {
                    self.filters.plan = Some(Plan::Pro);
                }
                if ui
                    .selectable_label(
                        self.filters.plan == Some(Plan::Ultra),
                        format!("Ultra ({ultra_count})"),
                    )
                    .clicked()
                {
                    self.filters.plan = Some(Plan::Ultra);
                }

                ui.add_space(12.0);
                ui.separator();
                ui.add_space(8.0);

                ui.label(egui::RichText::new("Thẻ (Tags)").strong());
                let mut all_tags = BTreeSet::new();
                for acc in accounts {
                    for tag in &acc.tags {
                        all_tags.insert(tag.clone());
                    }
                }

                if all_tags.is_empty() {
                    ui.weak("Chưa có tag nào");
                } else {
                    egui::ScrollArea::vertical()
                        .id_salt("left_tags_scroll")
                        .show(ui, |ui| {
                            for tag in all_tags {
                                let is_active = self.filters.tag.as_deref() == Some(&tag);
                                let count = accounts
                                    .iter()
                                    .filter(|a| a.tags.iter().any(|t| t.eq_ignore_ascii_case(&tag)))
                                    .count();
                                let label = format!("{tag} ({count})");
                                if ui.selectable_label(is_active, label).clicked() {
                                    if is_active {
                                        self.filters.tag = None;
                                    } else {
                                        self.filters.tag = Some(tag);
                                    }
                                }
                            }
                        });
                }

                if self.filters.plan.is_some()
                    || self.filters.status.is_some()
                    || self.filters.tag.is_some()
                    || !self.filters.text.is_empty()
                {
                    ui.add_space(16.0);
                    if ui.button("Xóa tất cả bộ lọc").clicked() {
                        self.filters = Filters::default();
                    }
                }
            });

        // Right sidepanel (editor)
        let mut editor_action = None;
        if let Some(ref mut draft) = self.draft {
            egui::SidePanel::right("main_editor_panel")
                .resizable(true)
                .default_width(320.0)
                .show(ctx, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("editor_scroll")
                        .show(ui, |ui| {
                            ui.heading(if draft.is_new {
                                "Tạo tài khoản mới"
                            } else {
                                "Chi tiết tài khoản"
                            });
                            ui.add_space(8.0);

                            egui::Grid::new("editor_grid")
                                .num_columns(2)
                                .spacing([10.0, 8.0])
                                .show(ui, |ui| {
                                    ui.label("Email:");
                                    ui.text_edit_singleline(&mut draft.account.email);
                                    ui.end_row();

                                    ui.label("Mật khẩu:");
                                    ui.horizontal(|ui| {
                                        ui.text_edit_singleline(&mut draft.account.password);
                                        if ui
                                            .button("📋")
                                            .on_hover_text("Sao chép mật khẩu")
                                            .clicked()
                                        {
                                            ctx.copy_text(draft.account.password.clone());
                                        }
                                    });
                                    ui.end_row();

                                    ui.label("Plan:");
                                    egui::ComboBox::from_id_salt("editor_plan_combo")
                                        .selected_text(draft.account.plan.as_str())
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(
                                                &mut draft.account.plan,
                                                Plan::Free,
                                                "Free",
                                            );
                                            ui.selectable_value(
                                                &mut draft.account.plan,
                                                Plan::Pro,
                                                "Pro",
                                            );
                                            ui.selectable_value(
                                                &mut draft.account.plan,
                                                Plan::Ultra,
                                                "Ultra",
                                            );
                                        });
                                    ui.end_row();

                                    ui.label("Trạng thái:");
                                    egui::ComboBox::from_id_salt("editor_status_combo")
                                        .selected_text(draft.account.status.as_str())
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(
                                                &mut draft.account.status,
                                                AccountStatus::Active,
                                                "Active",
                                            );
                                            ui.selectable_value(
                                                &mut draft.account.status,
                                                AccountStatus::Banned,
                                                "Banned",
                                            );
                                            ui.selectable_value(
                                                &mut draft.account.status,
                                                AccountStatus::Sold,
                                                "Sold",
                                            );
                                            ui.selectable_value(
                                                &mut draft.account.status,
                                                AccountStatus::Deleted,
                                                "Deleted",
                                            );
                                        });
                                    ui.end_row();

                                    ui.label("Tags (phân cách phẩy):");
                                    ui.text_edit_singleline(&mut self.tags_input);
                                    ui.end_row();

                                    ui.label("Email khôi phục:");
                                    let mut rec_email =
                                        draft.account.recovery_email.clone().unwrap_or_default();
                                    if ui.text_edit_singleline(&mut rec_email).changed() {
                                        draft.account.recovery_email =
                                            if rec_email.trim().is_empty() {
                                                None
                                            } else {
                                                Some(rec_email)
                                            };
                                    }
                                    ui.end_row();

                                    ui.label("SĐT khôi phục:");
                                    let mut rec_phone =
                                        draft.account.recovery_phone.clone().unwrap_or_default();
                                    if ui.text_edit_singleline(&mut rec_phone).changed() {
                                        draft.account.recovery_phone =
                                            if rec_phone.trim().is_empty() {
                                                None
                                            } else {
                                                Some(rec_phone)
                                            };
                                    }
                                    ui.end_row();

                                    ui.label("TOTP Secret:");
                                    let mut totp =
                                        draft.account.totp_secret.clone().unwrap_or_default();
                                    if ui.text_edit_singleline(&mut totp).changed() {
                                        draft.account.totp_secret = if totp.trim().is_empty() {
                                            None
                                        } else {
                                            Some(totp)
                                        };
                                    }
                                    ui.end_row();

                                    ui.label("Ghi chú:");
                                    let mut notes_text =
                                        draft.account.notes.clone().unwrap_or_default();
                                    if ui.text_edit_multiline(&mut notes_text).changed() {
                                        draft.account.notes = if notes_text.trim().is_empty() {
                                            None
                                        } else {
                                            Some(notes_text)
                                        };
                                    }
                                    ui.end_row();
                                });

                            if let Err(err) = draft.validate() {
                                ui.add_space(6.0);
                                ui.colored_label(egui::Color32::RED, format!("⚠ {err}"));
                            }

                            ui.add_space(12.0);
                            ui.separator();
                            ui.add_space(8.0);

                            ui.horizontal_wrapped(|ui| {
                                let can_save = draft.validate().is_ok();
                                if ui
                                    .add_enabled(can_save, egui::Button::new("💾 Lưu (Ctrl+S)"))
                                    .clicked()
                                {
                                    draft.account.tags = self
                                        .tags_input
                                        .split(',')
                                        .map(|s| s.trim().to_string())
                                        .filter(|s| !s.is_empty())
                                        .collect();
                                    editor_action =
                                        Some(EditorAction::Save(draft.clone().into_account()));
                                }

                                if !draft.is_new {
                                    if ui.button("🕒 Đã dùng").clicked() {
                                        editor_action =
                                            Some(EditorAction::MarkUsed(draft.account.id));
                                    }

                                    if !self.confirm_delete {
                                        if ui.button("🗑 Xóa").clicked() {
                                            self.confirm_delete = true;
                                        }
                                    } else {
                                        ui.colored_label(egui::Color32::RED, "Xóa?");
                                        if ui
                                            .button(
                                                egui::RichText::new("Xác nhận xóa")
                                                    .color(egui::Color32::RED),
                                            )
                                            .clicked()
                                        {
                                            editor_action =
                                                Some(EditorAction::Delete(draft.account.id));
                                        }
                                        if ui.button("Hủy").clicked() {
                                            self.confirm_delete = false;
                                        }
                                    }
                                }

                                if ui.button("Đóng (Esc)").clicked() {
                                    editor_action = Some(EditorAction::Close);
                                }
                            });
                        });
                });
        }

        match editor_action {
            Some(EditorAction::Save(acc)) => {
                self.selected = Some(acc.id);
                let _ = handle.tx.send(VaultCommand::Save(acc));
            }
            Some(EditorAction::MarkUsed(id)) => {
                let _ = handle.tx.send(VaultCommand::MarkUsed(id));
            }
            Some(EditorAction::Delete(id)) => {
                let _ = handle.tx.send(VaultCommand::Delete(id));
                self.draft = None;
                self.confirm_delete = false;
                self.selected = None;
            }
            Some(EditorAction::Close) => {
                self.draft = None;
                self.confirm_delete = false;
            }
            None => {}
        }

        // Central table
        egui::CentralPanel::default().show(ctx, |ui| {
            if accounts.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(80.0);
                    ui.heading("Chưa có tài khoản nào trong Vault");
                    ui.add_space(10.0);
                    ui.label("Hãy thêm tài khoản đầu tiên hoặc nhập danh sách từ file.");
                    ui.add_space(16.0);
                    if ui.button("+ Tạo tài khoản mới").clicked() {
                        self.selected = None;
                        self.draft = Some(EditorDraft::new());
                        self.confirm_delete = false;
                        self.tags_input.clear();
                    }
                });
                return;
            }

            let filtered = self.filters.apply(accounts);
            let mut sorted = filtered;
            sort_accounts(&mut sorted, &self.sort);

            if sorted.is_empty() {
                ui.vertical_centered(|ui| {
                    ui.add_space(50.0);
                    ui.label("Không tìm thấy tài khoản nào khớp với bộ lọc tìm kiếm.");
                    if ui.button("Xóa bộ lọc").clicked() {
                        self.filters = Filters::default();
                    }
                });
                return;
            }

            let table = TableBuilder::new(ui)
                .striped(true)
                .resizable(true)
                .cell_layout(Layout::left_to_right(Align::Center))
                .column(Column::initial(180.0).at_least(100.0))
                .column(Column::initial(60.0).at_least(40.0))
                .column(Column::initial(70.0).at_least(50.0))
                .column(Column::initial(110.0).at_least(80.0))
                .column(Column::initial(90.0).at_least(60.0))
                .column(Column::initial(90.0).at_least(60.0))
                .column(Column::initial(120.0).at_least(60.0))
                .column(Column::remainder());

            let mut clicked_acc = None;
            let mut double_clicked_email = None;

            table
                .header(24.0, |mut header| {
                    header.col(|ui| {
                        ui.strong("Email");
                    });
                    header.col(|ui| {
                        ui.strong("Plan");
                    });
                    header.col(|ui| {
                        ui.strong("Trạng thái");
                    });
                    header.col(|ui| {
                        ui.strong("Ngày tạo");
                    });
                    header.col(|ui| {
                        ui.strong("Hết hạn");
                    });
                    header.col(|ui| {
                        ui.strong("Dùng gần nhất");
                    });
                    header.col(|ui| {
                        ui.strong("Tags");
                    });
                    header.col(|ui| {
                        ui.strong("Cập nhật");
                    });
                })
                .body(|body| {
                    let row_height = 22.0;
                    let num_rows = sorted.len();
                    body.rows(row_height, num_rows, |mut row| {
                        let acc = sorted[row.index()];
                        let is_selected = self.selected == Some(acc.id);
                        row.set_selected(is_selected);

                        row.col(|ui| {
                            ui.label(&acc.email);
                        });
                        row.col(|ui| {
                            ui.label(acc.plan.as_str());
                        });
                        row.col(|ui| {
                            ui.label(acc.status.as_str());
                        });
                        row.col(|ui| {
                            let text = if let Some(d) = acc.created_on {
                                let today = chrono::Utc::now().date_naive();
                                let days = (today - d).num_days();
                                format!("{} ({}d)", d, days)
                            } else {
                                "-".into()
                            };
                            ui.label(text);
                        });
                        row.col(|ui| {
                            ui.label(
                                acc.expires_on
                                    .map(|d| d.to_string())
                                    .unwrap_or_else(|| "-".into()),
                            );
                        });
                        row.col(|ui| {
                            ui.label(
                                acc.last_used_on
                                    .map(|d| d.to_string())
                                    .unwrap_or_else(|| "-".into()),
                            );
                        });
                        row.col(|ui| {
                            ui.label(acc.tags.join(", "));
                        });
                        row.col(|ui| {
                            ui.label(acc.updated_at.format("%Y-%m-%d %H:%M").to_string());
                        });

                        let resp = row.response();
                        if resp.clicked() {
                            clicked_acc = Some(acc);
                        }
                        if resp.double_clicked() {
                            double_clicked_email = Some(acc.email.clone());
                        }
                    });
                });

            if let Some(acc) = clicked_acc {
                self.selected = Some(acc.id);
                self.draft = Some(EditorDraft::from_account(acc));
                self.confirm_delete = false;
                self.tags_input = acc.tags.join(", ");
            }
            if let Some(email) = double_clicked_email {
                ctx.copy_text(email);
            }
        });

        lock_requested
    }
}
