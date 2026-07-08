-- EXCITE plus Vital DB / MariaDB schema proposal
-- 운영 전 병원 전산·보안 검토가 필요합니다.
-- 실제 등록번호는 연구 데이터와 분리하고 암호화 저장하는 구조를 전제로 합니다.

CREATE TABLE app_user (
  user_id VARCHAR(64) PRIMARY KEY,
  login_id VARCHAR(100) NOT NULL UNIQUE,
  display_name VARCHAR(100) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role_code VARCHAR(30) NOT NULL,
  approval_status VARCHAR(30) NOT NULL,
  created_at DATETIME NOT NULL,
  last_login_at DATETIME NULL
);

CREATE TABLE patient_master (
  patient_id VARCHAR(64) PRIMARY KEY,
  pseudonym_initial VARCHAR(30) NULL,
  sex_code VARCHAR(20) NULL,
  birth_date DATE NULL,
  height_cm DECIMAL(7,2) NULL,
  weight_kg DECIMAL(7,2) NULL,
  admission_date DATE NULL,
  baseline_date DATE NULL,
  baseline_history_json JSON NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE patient_identifier_restricted (
  patient_id VARCHAR(64) PRIMARY KEY,
  encrypted_registration_no VARBINARY(512) NOT NULL,
  encrypted_patient_name VARBINARY(512) NULL,
  registration_no_hash CHAR(64) NOT NULL UNIQUE,
  masked_registration_no VARCHAR(20) NOT NULL,
  encryption_key_version VARCHAR(30) NOT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  CONSTRAINT fk_identifier_patient FOREIGN KEY (patient_id) REFERENCES patient_master(patient_id)
);

CREATE TABLE ecmo_episode (
  episode_id VARCHAR(64) PRIMARY KEY,
  patient_id VARCHAR(64) NOT NULL,
  episode_sequence INT NOT NULL,
  episode_label VARCHAR(100) NOT NULL,
  ecmo_type VARCHAR(100) NULL,
  ecmo_mode VARCHAR(30) NULL,
  procedure_location VARCHAR(100) NULL,
  drain_site VARCHAR(100) NULL,
  return_site VARCHAR(100) NULL,
  drain_cannula_fr DECIMAL(6,2) NULL,
  return_cannula_fr DECIMAL(6,2) NULL,
  total_perfusion_count INT NULL,
  circuit_change_count INT NULL,
  management_method VARCHAR(30) NULL,
  crp_flag_pending_name_check VARCHAR(30) NULL,
  crrt_flag BOOLEAN NULL,
  crrt_start_at DATETIME NULL,
  crrt_end_at DATETIME NULL,
  crrt_mode VARCHAR(100) NULL,
  crrt_note TEXT NULL,
  creatinine_28d DECIMAL(12,4) NULL,
  creatinine_28d_unit VARCHAR(50) NULL,
  last_followup_date DATE NULL,
  complication_note TEXT NULL,
  circuit_change_note TEXT NULL,
  followup_note TEXT NULL,
  discharge_alive VARCHAR(20) NULL,
  episode_note TEXT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  UNIQUE KEY uq_patient_episode_seq (patient_id, episode_sequence),
  CONSTRAINT fk_episode_patient FOREIGN KEY (patient_id) REFERENCES patient_master(patient_id)
);

CREATE TABLE episode_event (
  episode_event_id VARCHAR(64) PRIMARY KEY,
  episode_id VARCHAR(64) NOT NULL,
  event_name VARCHAR(100) NOT NULL,
  event_at DATETIME NULL,
  event_type VARCHAR(50) NULL,
  event_note TEXT NULL,
  CONSTRAINT fk_event_episode FOREIGN KEY (episode_id) REFERENCES ecmo_episode(episode_id)
);

CREATE TABLE episode_vent_flow_vital (
  measurement_id VARCHAR(64) PRIMARY KEY,
  episode_id VARCHAR(64) NOT NULL,
  episode_event_id VARCHAR(64) NULL,
  reference_timepoint VARCHAR(100) NULL,
  measured_at DATETIME NULL,
  vent_mode VARCHAR(100) NULL,
  fio2 DECIMAL(12,4) NULL,
  rr DECIMAL(12,4) NULL,
  peep DECIMAL(12,4) NULL,
  pip DECIMAL(12,4) NULL,
  flow_rate DECIMAL(12,4) NULL,
  o2_value DECIMAL(12,4) NULL,
  o2_unit VARCHAR(30) NULL,
  sbp DECIMAL(12,4) NULL,
  dbp DECIMAL(12,4) NULL,
  mean_bp DECIMAL(12,4) NULL,
  pr DECIMAL(12,4) NULL,
  spap DECIMAL(12,4) NULL,
  dpap DECIMAL(12,4) NULL,
  mean_pap DECIMAL(12,4) NULL,
  CONSTRAINT fk_vfv_episode FOREIGN KEY (episode_id) REFERENCES ecmo_episode(episode_id),
  CONSTRAINT fk_vfv_event FOREIGN KEY (episode_event_id) REFERENCES episode_event(episode_event_id)
);

CREATE TABLE laboratory_result (
  lab_result_id VARCHAR(64) PRIMARY KEY,
  patient_id VARCHAR(64) NOT NULL,
  episode_id VARCHAR(64) NULL,
  test_name VARCHAR(100) NOT NULL,
  result_value DECIMAL(18,6) NULL,
  result_text VARCHAR(255) NULL,
  unit VARCHAR(50) NULL,
  tested_at DATETIME NULL,
  reference_timepoint VARCHAR(100) NULL,
  note TEXT NULL,
  source_file_id VARCHAR(64) NULL,
  source_linked BOOLEAN NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  CONSTRAINT fk_lab_patient FOREIGN KEY (patient_id) REFERENCES patient_master(patient_id),
  CONSTRAINT fk_lab_episode FOREIGN KEY (episode_id) REFERENCES ecmo_episode(episode_id)
);

CREATE TABLE microbiology_result (
  microbiology_result_id VARCHAR(64) PRIMARY KEY,
  patient_id VARCHAR(64) NOT NULL,
  episode_id VARCHAR(64) NULL,
  collection_date DATE NOT NULL,
  collection_time TIME NULL,
  specimen_site VARCHAR(100) NULL,
  organism_name VARCHAR(255) NOT NULL,
  result_code CHAR(1) NOT NULL,
  culture_set VARCHAR(100) NULL,
  susceptibility_result TEXT NULL,
  laboratory_name VARCHAR(150) NULL,
  duplicate_override BOOLEAN NOT NULL DEFAULT FALSE,
  duplicate_reason TEXT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  UNIQUE KEY uq_micro_patient_date_organism (patient_id, collection_date, organism_name),
  CONSTRAINT fk_micro_patient FOREIGN KEY (patient_id) REFERENCES patient_master(patient_id),
  CONSTRAINT fk_micro_episode FOREIGN KEY (episode_id) REFERENCES ecmo_episode(episode_id)
);

CREATE TABLE research_tag (
  tag_id VARCHAR(64) PRIMARY KEY,
  tag_name VARCHAR(150) NOT NULL UNIQUE,
  tag_description TEXT NULL,
  color_hex CHAR(7) NULL,
  created_by VARCHAR(64) NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE tag_tree_node (
  node_id VARCHAR(64) PRIMARY KEY,
  tag_id VARCHAR(64) NOT NULL,
  parent_node_id VARCHAR(64) NULL,
  node_type VARCHAR(20) NOT NULL, -- tag, question, value
  node_name VARCHAR(255) NOT NULL,
  selection_mode VARCHAR(20) NULL, -- single, multiple
  sort_order INT NOT NULL DEFAULT 0,
  description TEXT NULL,
  is_collapsed BOOLEAN NOT NULL DEFAULT FALSE,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  CONSTRAINT fk_tree_tag FOREIGN KEY (tag_id) REFERENCES research_tag(tag_id),
  CONSTRAINT fk_tree_parent FOREIGN KEY (parent_node_id) REFERENCES tag_tree_node(node_id)
);

CREATE TABLE tag_assignment (
  assignment_id VARCHAR(64) PRIMARY KEY,
  tag_id VARCHAR(64) NOT NULL,
  target_type VARCHAR(30) NOT NULL, -- patient, episode, lab, csv
  target_id VARCHAR(64) NOT NULL,
  selected_path_json JSON NOT NULL,
  note TEXT NULL,
  assigned_by VARCHAR(64) NOT NULL,
  assigned_at DATETIME NOT NULL,
  CONSTRAINT fk_assignment_tag FOREIGN KEY (tag_id) REFERENCES research_tag(tag_id)
);


CREATE TABLE monitor_room (
  monitor_room_id VARCHAR(64) PRIMARY KEY,
  room_name VARCHAR(100) NOT NULL UNIQUE,
  room_color_hex CHAR(7) NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

CREATE TABLE monitor_patient_assignment (
  monitor_assignment_id VARCHAR(64) PRIMARY KEY,
  room_name VARCHAR(100) NOT NULL,
  monitor_number VARCHAR(50) NOT NULL,
  patient_id VARCHAR(64) NOT NULL,
  assigned_start_at DATETIME NOT NULL,
  assigned_end_at DATETIME NOT NULL,
  display_order INT NOT NULL DEFAULT 0,
  created_by VARCHAR(64) NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  INDEX idx_monitor_assignment_lookup (room_name, monitor_number, assigned_start_at, assigned_end_at),
  INDEX idx_monitor_assignment_patient (patient_id, assigned_start_at),
  CONSTRAINT fk_monitor_assignment_patient FOREIGN KEY (patient_id) REFERENCES patient_master(patient_id)
);

CREATE TABLE csv_file_metadata (
  csv_file_id VARCHAR(64) PRIMARY KEY,
  patient_id VARCHAR(64) NULL,
  episode_id VARCHAR(64) NULL,
  case_id VARCHAR(150) NULL,
  original_file_name VARCHAR(255) NOT NULL,
  monitor_room VARCHAR(100) NULL,
  monitor_number VARCHAR(50) NULL,
  filename_recorded_at DATETIME NULL,
  monitor_assignment_id VARCHAR(64) NULL,
  match_source VARCHAR(50) NULL,
  storage_path TEXT NOT NULL,
  feature_file_path TEXT NULL,
  file_size BIGINT NULL,
  row_count BIGINT NULL,
  data_start_at DATETIME NULL,
  data_end_at DATETIME NULL,
  upload_status VARCHAR(30) NOT NULL,
  match_status VARCHAR(30) NOT NULL,
  match_failure_reason VARCHAR(255) NULL,
  uploaded_by VARCHAR(64) NOT NULL,
  uploaded_at DATETIME NOT NULL,
  matched_at DATETIME NULL,
  CONSTRAINT fk_csv_patient FOREIGN KEY (patient_id) REFERENCES patient_master(patient_id),
  CONSTRAINT fk_csv_episode FOREIGN KEY (episode_id) REFERENCES ecmo_episode(episode_id),
  CONSTRAINT fk_csv_monitor_assignment FOREIGN KEY (monitor_assignment_id) REFERENCES monitor_patient_assignment(monitor_assignment_id)
);

CREATE TABLE audit_log (
  audit_id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id VARCHAR(64) NULL,
  action_code VARCHAR(100) NOT NULL,
  target_type VARCHAR(50) NOT NULL,
  target_id VARCHAR(64) NULL,
  description TEXT NULL,
  client_ip VARCHAR(64) NULL,
  occurred_at DATETIME NOT NULL
);


CREATE TABLE time_series_analysis_spec (
  analysis_spec_id VARCHAR(64) PRIMARY KEY,
  project_id VARCHAR(64) NULL,
  tag_id VARCHAR(64) NULL,
  patient_id VARCHAR(64) NULL,
  analysis_scope VARCHAR(50) NOT NULL, -- within_file, within_patient, between_patient, ecmo_outcome
  primary_signal VARCHAR(100) NOT NULL,
  study_question TEXT NULL,
  time_range_text VARCHAR(255) NULL,
  source_a_id VARCHAR(64) NULL,
  methods_json JSON NOT NULL,
  preprocessing_json JSON NOT NULL,
  model_json JSON NOT NULL,
  requested_outputs_json JSON NOT NULL,
  status VARCHAR(30) NOT NULL,
  created_by VARCHAR(64) NOT NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL
);

-- 분석 그래프 편집 설정 예시
-- time_series_analysis_spec에 JSON 컬럼으로 저장하거나 별도 테이블로 분리할 수 있습니다.
ALTER TABLE time_series_analysis_spec
  ADD COLUMN IF NOT EXISTS graph_style_json JSON NULL COMMENT '제목, 축 제목, 계열 색상, 글꼴, 선 굵기, 범례/눈금선, 투명 배경';
